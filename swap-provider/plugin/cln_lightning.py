import asyncio
import os
import time
import traceback
from datetime import datetime
from typing import NamedTuple, Optional, Callable, Dict, Tuple, Any, List, Union
from enum import IntEnum, Enum
import threading
from decimal import Decimal

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID, Invoice, LN_EXPIRY_NEVER
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .constants import MIN_FINAL_CLTV_DELTA_FOR_CLIENT, MIN_FINAL_CLTV_DELTA_ACCEPTED, MIN_FINAL_CLTV_DELTA_FOR_INVOICE
from .utils import call_blocking_with_timeout, ShortID
from .lnutil import LnFeatures, filter_suitable_recv_chans, hex_to_bytes, bytes_to_hex
from .invoices import HoldInvoice, DuplicateInvoiceCreationError, Htlc, InvoiceState
from .lnaddr import LnAddr, lnencode_unsigned
from .bitcoin import COIN


class PaymentInfo(NamedTuple):
    payment_hash: bytes
    amount_msat: Optional[int]
    direction: int
    status: int


class Direction(IntEnum):
    SENT = -1     # in the context of HTLCs: "offered" HTLCs
    RECEIVED = 1  # in the context of HTLCs: "received" HTLCs


SAVED_PR_STATUS = [PR_PAID, PR_UNPAID] # status that are persisted
SENT = Direction.SENT
RECEIVED = Direction.RECEIVED


class PrepayGate(Enum):
    PROCEED = 1  # no prepay attached (single-set), or prepay FUNDED/SETTLED
    WAIT = 2     # main missing, or prepay attached but not yet fully funded
    ABORT = 3    # prepay attached but deleted (expired unfunded) — issue #3


class CLNLightning:
    INBOUND_LIQUIDITY_FACTOR = 0.9  # Buffer factor for inbound liquidity calculation (use only 90% of inbound capacity)

    def __init__(self, *, plugin_instance: CLNPlugin, config: PluginConfig, db: JsonDB, logger: PluginLogger):
        # self.MIN_FINAL_CLTV_DELTA_ACCEPTED: int = config.cln_config["cltv-final"]["value_int"]
        # self.MIN_FINAL_CLTV_DELTA_FOR_INVOICE: int = self.MIN_FINAL_CLTV_DELTA_ACCEPTED + 3

        self._rpc = plugin_instance.plugin.rpc
        self.plugin = plugin_instance
        self._config = config
        self._db = db
        self._logger = logger
        self._hold_invoice_callbacks = {}
        self._invoice_lock = threading.RLock()
        self._payment_info_lock = threading.RLock()
        self._preimages = db.get_dict('lightning_preimages')  # RHASH -> preimage
        self._invoices = db.get_dict('invoices')  # type: Dict[str, Invoice]
        self._hold_invoices = db.get_dict('hold_invoices')  # type: Dict[str, HoldInvoice]  # HASH[hex] -> bolt11
        # issue #25 (A5 sibling): persisted tombstones of deleted/expired
        # holds — replayed/late HTLCs for these FAIL (electrum reference:
        # lnpeer.py:3178 "payment info has been deleted" → 400F), never
        # "continue" (which parks payer funds until CLTV). Init here so the
        # hook is tombstone-safe before run() completes.
        self._tombstones = db.get_dict('hold_tombstones')
        # Issue #3: prepay-hash -> main-hash reverse index, so the expiry
        # sweeper can tear a bundled main down when its prepay dies unpaid.
        self._bundle_main_of = db.get_dict('bundle_main_of')
        self._decoded_invoices = {}  # bolt11 -> decoded dict (see handle_htlc)
        self._payment_secret_key = plugin_instance.derive_secret("payment_secret")
        self.monitoring_tasks = [] # type: List[asyncio.Task]
        self._logger.debug("CLNLightning initialized")

    async def run(self):
        # These loops are immortal BY DESIGN and must stay NON-DAEMON
        # threads: JsonDB.write refuses writes from daemon threads
        # ('daemon thread cannot write db' — an electrum-inherited
        # invariant), and monitor_expiries/callback_handler/the pyln hook
        # all persist invoices. Issue #16 therefore fixes the zombie at
        # the TOP level instead (swap-provider.py hard-exits on every
        # crash path, so asyncio.run's executor join — which would block
        # forever on these threads — is structurally unreachable). Do NOT
        # convert these to daemon threads.
        # put the htlc expiry monitoring in a separate thread to avoid blocking the async event loop
        htlc_expiry_watcher = asyncio.to_thread(self.monitor_expiries)
        self.monitoring_tasks.append(asyncio.create_task(htlc_expiry_watcher))

        # start the callback handler thread which checks if hold invoices are fully funded and calls the callback
        callback_handler = asyncio.to_thread(self.callback_handler)
        self.monitoring_tasks.append(asyncio.create_task(callback_handler))

        self.plugin.set_htlc_hook(self.plugin_htlc_accepted_hook)  # has to be last so other vars are init
        self._logger.debug("CLNLightning monitoring started")

    def monitor_expiries(self):
        """Iterate through the hold invoices and cancel expired htlcs"""
        # audit #23 A2: a permanently-broken invoice used to emit a full
        # traceback ERROR every 10s forever. Per-invoice error counters:
        # full detail on first occurrence, then 1-in-50 summary lines —
        # grep-able signal without the log-flood.
        err_counts: dict = {}
        while True:
            try:
                self._expire_pass(err_counts)
            except Exception:
                self._logger.error(f"monitor_expiries loop encountered an error:\n{traceback.format_exc()}")
            time.sleep(10)

    def _expire_pass(self, err_counts: dict):
        """One expiry sweep. Issue #6 (PD-3): failures are isolated
        PER-INVOICE — one poisoned entry must not starve the rest of
        the sweep (the old whole-loop try/except restarted from the top
        every 10s and died on the same entry forever)."""
        with self._invoice_lock:
            for payment_hash in list(self._hold_invoices.keys()):
                try:
                    invoice = self.get_hold_invoice(payment_hash)
                    # db round-trip hazard: after a restart the JsonDB
                    # may hold non-HoldInvoice values (bools from the
                    # flat tombstone store, plain dicts from stale
                    # serializations) — skip and purge them instead
                    # of crashing the monitor loop forever (earned:
                    # 'bool' object has no attribute 'cancel_all_htlcs'
                    # spun every 10s, blocking ALL expiry handling)
                    if not isinstance(invoice, HoldInvoice):
                        if invoice is not None:
                            self._logger.warning(
                                f"monitor_expiries: purging corrupt "
                                f"hold_invoices entry {payment_hash[:12]}… "
                                f"(type {type(invoice).__name__})")
                            self._hold_invoices.pop(payment_hash, None)
                        continue
                    if self.check_invoice_expiry(invoice):
                        self._logger.warning(f"monitor_expiries: "
                                             f"cancelled expired invoice {invoice.payment_hash.hex()}")
                    err_counts.pop(payment_hash, None)  # recovered — reset
                except Exception:
                    n = err_counts.get(payment_hash, 0) + 1
                    err_counts[payment_hash] = n
                    if n == 1 or n % 50 == 0:
                        self._logger.error(f"monitor_expiries: invoice "
                                       f"{payment_hash[:12]}… errored {n}× "
                                       f"(first occurrence logged in full; "
                                           f"summary every 50):\n"
                                       f"{traceback.format_exc()}")

    def check_invoice_expiry(self, invoice: HoldInvoice) -> bool:
        """Check if the invoice is expired and cancel it if it is, also checks associated prepay invoice"""
        if invoice is None:
            return False

        # FUNDED-abandonment watchdog (#28 residual, live 2026-08-25): a
        # fully-parked hold whose swap callback fired but the funding
        # never happened parks FOREVER — the sweeper deliberately skips
        # FUNDED (it's waiting for claim→settle), so the payer's HTLC
        # dangles to CLTV (~95min), pinning channel capacity and
        # cascading no-failcode routing failures into every later swap.
        # Settle is the ONLY valid exit from FUNDED; past expiry + a
        # grace window (callback retries, mempool lag), it is abandoned —
        # cancel. Grace = expiry again (300s default → ~10min total).
        # #80 (live 2026-08-30, ~53k signet): the FUNDED branch below
        # assumed "no settle ⇒ the swap's onchain funding never happened".
        # False: the callback had already dispatched the escrow funding,
        # and the client's claim — which settles this hold via
        # _finish_normal_swap — lands at CHAIN speed (blocks), not invoice
        # speed. Cancelling here burns the provider's onchain leg while
        # the preimage reveal is still in flight. A dispatched hold is
        # untouchable: park until the escrow resolves (claim → settle;
        # timeout → refund → _fail_swap cancels). The HTLC rides to CLTV
        # at worst — capacity pinning, never funds loss.
        if (invoice.funding_status is InvoiceState.FUNDED
                and invoice.funding_dispatched_at is not None):
            self._logger.info(
                f"check_invoice_expiry: funded hold {invoice.payment_hash.hex()} has onchain "
                f"funding dispatched ({int(time.time()) - invoice.funding_dispatched_at}s ago) "
                f"— leaving parked for escrow resolution (#80 guard)")
            return False

        if (invoice.funding_status is InvoiceState.FUNDED
                and invoice.created_at + invoice.expiry * 2 < time.time()):
            self._logger.warning(
                f"check_invoice_expiry: cancelling ABANDONED funded hold "
                f"{invoice.payment_hash.hex()} (parked {int(time.time()) - invoice.created_at}s, "
                f"no settle — swap funding never completed; #28 watchdog)")
            invoice.cancel_all_htlcs()
            self.unregister_hold_invoice_callback(invoice.payment_hash)
            self.delete_hold_invoice(invoice.payment_hash)
            return True

        # cancel all htlcs and delete invoice if it's expired
        if (invoice.created_at + invoice.expiry < time.time()
                and invoice.funding_status not in [InvoiceState.FUNDED, InvoiceState.SETTLED]):
            self._logger.warning(f"check_invoice_expiry: cancelling expired invoice {invoice.payment_hash.hex()}")
            invoice.cancel_all_htlcs()  # also cancel the prepay invoice!

            # Issue #3: if THIS expired hold is a bundled prepay, tear its
            # main down too — a funded main must never proceed without the
            # prepay (the callback used to fall through on prepay-is-None
            # and fund the onchain leg having received only main-minus-prepay).
            # (captured before delete: delete_hold_invoice also cleans the index)
            main_hash = self._bundle_main_of.get(invoice.payment_hash.hex())

            if invoice.associated_invoice is not None:
                self._logger.debug(f"deleting associated invoice: {invoice.associated_invoice}")
                # WALRUS PRECEDENCE (earned live): ':=' binds looser than
                # 'is not None' — without the parens, prepay_invoice got
                # the BOOLEAN (True), crashing cancel_all_htlcs every 10s
                if (prepay_invoice := self.get_hold_invoice(invoice.associated_invoice)) is not None:
                    self._logger.debug(f"prepay_invoice: {prepay_invoice}")
                    prepay_invoice.cancel_all_htlcs()
                    self.delete_hold_invoice(prepay_invoice.payment_hash)

            self.delete_hold_invoice(invoice.payment_hash)
            if main_hash is not None:
                main = self._hold_invoices.get(main_hash)
                if main is not None:
                    main.cancel_all_htlcs()
                    self.unregister_hold_invoice_callback(main.payment_hash)
                    self.delete_hold_invoice(main.payment_hash)
                    self._logger.warning(
                        f'check_invoice_expiry: prepay expired unfunded — cancelled '
                        f'bundled main invoice {main_hash} (payer HTLCs returned)')
            return True
        return False

    def _bundle_prepay_state(self, invoice: Optional[HoldInvoice],
                             prepay_invoice: Optional[HoldInvoice]) -> PrepayGate:
        """Gate for firing a bundled main's funding callback (issue #3).

        The old code treated prepay-is-None as 'settled-then-deleted' and
        fired anyway — but no code path deletes a settled prepay before the
        main callback; the real producer of None was the expiry sweeper, so
        swaps proceeded WITHOUT the prepay (R4/F8 broken, fee leak)."""
        if invoice is None:
            return PrepayGate.WAIT
        if invoice.get_prepay_invoice() is None:
            return PrepayGate.PROCEED  # not a bundled invoice
        if prepay_invoice is None:
            return PrepayGate.ABORT  # prepay vanished unfunded — never fund
        if prepay_invoice.funding_status in (InvoiceState.FUNDED, InvoiceState.SETTLED):
            return PrepayGate.PROCEED
        return PrepayGate.WAIT

    def callback_handler(self):
        """Iterate through the hold invoices and call the callback if the invoice is fully funded"""
        while True:
            time.sleep(5)
            try:
                for payment_hash, callback in list(self._hold_invoice_callbacks.items()):
                    with self._invoice_lock:
                        invoice = self.get_hold_invoice(payment_hash)
                        if invoice is None:
                            # no hold invoice has been saved before registering this callback
                            self._logger.error(f"callback_handler: hold invoice {payment_hash} not found")
                            # PORT FIND #10: pop(key, None) — the expiry
                            # sweeper's unregister_hold_invoice_callback can
                            # remove the entry between our items() snapshot
                            # and this pop; a bare pop raised KeyError and
                            # poisoned the iteration for every other swap
                            self._hold_invoice_callbacks.pop(payment_hash, None)
                            continue
                        if invoice.funding_status is InvoiceState.FUNDED:
                            prepay_invoice_hash = invoice.get_prepay_invoice()
                            prepay_invoice = self.get_hold_invoice(prepay_invoice_hash) \
                                if prepay_invoice_hash is not None else None
                            gate = self._bundle_prepay_state(invoice, prepay_invoice)
                            if gate is PrepayGate.WAIT:
                                continue
                            if gate is PrepayGate.ABORT:
                                # Issue #3: the sweeper should have torn this
                                # main down with its expired prepay; if we
                                # still see it, fail safe NOW — cancel the
                                # payer's HTLCs, never fund on a broken bundle.
                                self._logger.error(
                                    f"callback_handler: bundled prepay "
                                    f"{prepay_invoice_hash.hex()} of {invoice.payment_hash.hex()} "
                                    f"vanished unfunded — cancelling main (issue #3)")
                                invoice.cancel_all_htlcs()
                                self.unregister_hold_invoice_callback(invoice.payment_hash)
                                self.delete_hold_invoice(invoice.payment_hash)
                                continue
                            if prepay_invoice is not None:
                                # redeem the prepay invoice first
                                prepay_invoice.settle(self.get_preimage(prepay_invoice_hash))
                                self.update_invoice(prepay_invoice)
                                self._logger.debug(f"callback_handler: prepay invoice "
                                                   f"{prepay_invoice.payment_hash.hex()} redeemed")
                            # #23/#28: the funding-callback dispatch IS the
                            # money moment — if it silently no-ops (empty
                            # registry after restart, the #28 class), only
                            # this line distinguishes "never called" from
                            # "called and failed". Default-visible.
                            self._logger.info(f"callback_handler: invoice {invoice.payment_hash.hex()} fully funded, "
                                                f"calling callback")

                            # Call the callback
                            callback(invoice.payment_hash)
                            self.unregister_hold_invoice_callback(invoice.payment_hash)
                            # #80: the FUNDED-abandonment watchdog below must
                            # never cancel a hold whose swap already committed
                            # onchain funds — the escrow's resolution (client
                            # claim → _finish_normal_swap settles this hold
                            # with the extracted preimage; escrow timeout →
                            # refund → _fail_swap cancels it) is the only safe
                            # exit once money is on the chain. Record it
                            # persistently (JsonDB) so it survives restarts.
                            invoice.funding_dispatched_at = int(time.time())
                            self.update_invoice(invoice)
                            self._logger.info(f"callback_handler: callback returned for "
                                                f"{invoice.payment_hash.hex()} — funding dispatched")

            except Exception as e:
                self._logger.error(f"callback_handler encountered an error:\n{traceback.format_exc()}")

    def plugin_htlc_accepted_hook(self, onion, htlc, request, plugin, *args, **kwargs) -> None:
        if "forward_to" in kwargs:  # ignore forwards
            self._logger.debug(f"plugin_htlc_accepted_hook: ignoring forward htlc")
            return request.set_result({"result": "continue"})

        with self._invoice_lock:
            payment_hash_hex = htlc["payment_hash"]
            invoice = self.get_hold_invoice(bytes.fromhex(payment_hash_hex))
            if invoice is None:  # htlc doesn't belong to a hold invoice we know about
                if payment_hash_hex in self._tombstones:
                    # hold deleted/expired (issue #25): fail immediately —
                    # mirrors invoices.Htlc.fail()'s 400F shape
                    self._logger.info(f"plugin_htlc_accepted_hook: failing htlc for "
                                      f"tombstoned hold {payment_hash_hex[:12]}…")
                    return request.set_result({"result": "fail",
                                               "failure_message": "400F"})
                self._logger.debug(f"plugin_htlc_accepted_hook: htlc for unknown invoice")
                return request.set_result({"result": "continue"})

            # htlc that affects one of our stored hold invoices
            try:
                if self.handle_htlc(invoice, htlc, onion, request):
                    self.update_invoice(invoice)  # saves the changes to the invoice
            except Exception:
                self._logger.error(f"plugin_htlc_accepted_hook failed:\n{traceback.format_exc()}")
                return request.set_result({"result": "continue"})

    def update_invoice(self, invoice: HoldInvoice) -> None:
        """Update the invoice in the db so it reflects all internal changes by calling __setattr__ in the StoredDict"""
        self._hold_invoices.pop(invoice.payment_hash.hex())
        self._hold_invoices[invoice.payment_hash.hex()] = invoice
        self._db.write()

    def handle_htlc(self, target_invoice: HoldInvoice, incoming_htlc: dict[str, Any], onion, request) -> bool:
        """Validates and stores the incoming htlc, returns True if changes need to be saved in db
        CLN will replay all unresolved HTLCs on restart"""
        self._logger.debug(f"handle_htlc: {incoming_htlc}")
        htlc = Htlc.from_cln_dict(incoming_htlc, request)
        if (existing := target_invoice.find_htlc(htlc)) is not None:
            existing.add_new_htlc_callback(request)
            self._logger.debug(f"handle_htlc: registering new cln callback for existing htlc, "
                               f"targeted invoice: {target_invoice.payment_hash.hex()}")
            return False # we already received this htlc and don't have to store it again (e.g. after replay when restarting)
        else:
            # add the htlc to the invoice
            target_invoice.incoming_htlcs.add(htlc)

        try:
            # PORT FIND #12: CLN v26 removed `decodepay`; `decode` returns
            # the same fields for bolt11 (payment_secret, min_final_cltv).
            # Cached: CLN replays unresolved HTLCs on every restart — no
            # need to re-RPC for an invoice we already decoded.
            if target_invoice.bolt11 in self._decoded_invoices:
                decoded_invoice = self._decoded_invoices[target_invoice.bolt11]
            else:
                decoded_invoice = self._rpc.decode(target_invoice.bolt11)
                self._decoded_invoices[target_invoice.bolt11] = decoded_invoice
        except Exception as e:
            self._logger.error(f"handle_htlc: decode rpc failed: {e}")
            htlc.fail()
            return True

        if target_invoice.funding_status is InvoiceState.FAILED:
            # invoice is already failed, we don't accept any further htlcs for it
            self._logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already failed")
            htlc.fail()
            return True

        if (incoming_htlc["cltv_expiry_relative"] < decoded_invoice["min_final_cltv_expiry"] or
            incoming_htlc["cltv_expiry_relative"] < MIN_FINAL_CLTV_DELTA_ACCEPTED):
            self._logger.warning(f"handle_htlc: Too short cltv: ({incoming_htlc['cltv_expiry_relative']} < "
                               f"{decoded_invoice['min_final_cltv_expiry']})")
            htlc.fail()
            return True

        # check if the payment secret is correct (and existing)
        if "payment_secret" not in onion or onion["payment_secret"] != decoded_invoice["payment_secret"]:
            self._logger.warning(f"handle_htlc: htlc with none or incorrect payment secret for "
                                  f"invoice {target_invoice.payment_hash}")
            htlc.fail()
            return True

        if target_invoice.funding_status != InvoiceState.UNFUNDED:
            self._logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already paid, "
                                  f"no new htlcs accepted")
            htlc.fail()
            return True

        # check if we now have enough htlcs to satisfy the invoice, redeem them if so
        if target_invoice.is_fully_funded():
            target_invoice.funding_status = InvoiceState.FUNDED

        self._logger.debug(f"handle_htlc: htlc accepted for invoice {target_invoice.payment_hash.hex()}, "
                           f"value: {htlc.amount_msat}")
        return True

    async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
        self._logger.debug("pay_invoice: " + bolt11)
        # #14 item 1: listpays(bolt11=...) returns a LIST of payment
        # objects, not a single dict — the old ['status'] subscript threw
        # TypeError on every call, the except swallowed it, and the dedup
        # short-circuit never ran. CLN-level dedup masked the impact.
        try:
            pays = self._rpc.listpays(bolt11=bolt11)
            pays_list = pays if isinstance(pays, list) else pays.get('pays', [])
            for p in pays_list:
                if p.get('status') == 'complete':
                    return True, p.get('preimage', '')
                elif p.get('status') == 'pending':
                    return False, f"payment is already pending for this bolt11"
        except Exception:
            pass

        retry_for = attempts * 45 if attempts > 1 else 60  # CLN automatically retries for the given amount of time
        try:
            # result = await call_blocking_with_timeout(self._rpc.pay(bolt11=bolt11, retry_for=retry_for),  // wrong call
            #                                     timeout=retry_for + 30)
            result = await asyncio.to_thread(self._rpc.pay, bolt11=bolt11, retry_for=retry_for)
        except Exception as e:
            return False, "pay_invoice call to CLN failed: " + str(e)

        self._logger.debug(f"pay_invoice call result: {result}")
        if 'payment_preimage' in result and result['payment_preimage'] and result['status'] == 'complete':
            return True, result['payment_preimage']
        return False, result

    def create_payment_info(self, *, amount_msat: Optional[int], write_to_disk=True) -> bytes:
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        self.save_preimage(payment_hash, payment_preimage, write_to_disk=True)
        return payment_hash

    def save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise InvalidPreimageSavedError("tried to save incorrect preimage for payment_hash")
        self._preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            self._db.write()

    def delete_payment_info(self, payment_hash: Union[bytes, str], write_db: bool = True) -> None:
        """Used to delete remaining payment info after a swap has been completed or failed"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        with self._payment_info_lock:
            preimage_res = self._preimages.pop(payment_hash, None)
        if preimage_res is None:
            return
        if write_db:
            self._db.write()

    def save_invoice(self, invoice: Invoice, *, write_to_disk: bool = True) -> None:
        key = invoice.get_id()
        if not invoice.is_lightning():
            raise NotImplementedError("save_invoice: only lightning invoices are supported")
        self._invoices[key] = invoice
        if write_to_disk:
            self._db.write()

    def get_invoice(self, key: str) -> Optional[Invoice]:
        return self._invoices.get(key)

    def get_payment_statuses(self, payment_hash_hex: str) -> List[str]:
        """Statuses of the CLN payment attempts for a payment hash.
        Returns an empty list if no payment was ever attempted (note that
        listpays returns {'pays': [...]}, there is no top-level 'status')."""
        try:
            pays = self._rpc.listpays(payment_hash=payment_hash_hex).get('pays', [])
        except Exception as e:
            self._logger.error(f"get_payment_statuses: listpays rpc failed: {e}")
            return []
        return [p.get('status') for p in pays]

    def get_hold_invoice(self, payment_hash: Union[str, bytes]) -> Optional[HoldInvoice]:
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        return self._hold_invoices.get(payment_hash, None)

    def delete_invoice(self, key: Union[bytes, str], write_db: bool = True) -> None:
        if isinstance(key, bytes):
            key = key.hex()
        inv = self._invoices.pop(key, None)
        if inv is None:
            return
        if write_db:
            self._db.write()

    def get_regular_bolt11_invoice(  # we generate the preimage
            self, *,
            amount_msat: Optional[int],
            message: str,
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str],
            min_final_cltv_expiry_delta: Optional[int] = None,
            preimage: Optional[bytes] = None,
    ) -> Tuple[str, str]:  # -> (bolt11, label)
        preimage_hex = None
        if preimage:
            preimage_hex = preimage.hex() if preimage else None
        label_hex = os.urandom(8).hex()  # unique internal identifier, can be used to fetch invoice status later
        amount_msat = "any" if amount_msat is None else amount_msat

        try:
            result = self._rpc.invoice(amount_msat=amount_msat,  # any for 0 amount invoices
                                                    label=label_hex,  # unique internal identifier
                                                    description=message,
                                                    expiry=expiry,
                                                    fallbacks=fallback_address,
                                                    preimage=preimage_hex,
                                                    cltv=min_final_cltv_expiry_delta,
                                                    exposeprivatechannels=True
                                                    )
            bolt11 = result['bolt11']
        except Exception as e:
            raise ClnRpcError("get_bolt11_invoice call to CLN failed: " + str(e))
        return bolt11, label_hex

    def register_hold_invoice_callback(self, payment_hash: Union[bytes, str], callback: Callable) -> None:
        """Used to register the swap invoice (not prepay invoice) with the callback manager"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        self._hold_invoice_callbacks[payment_hash] = callback

    def unregister_hold_invoice_callback(self, payment_hash: Union[bytes, str]) -> None:
        """Used to unregister the swap invoice from the callback manager"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        self._hold_invoice_callbacks.pop(payment_hash, None)

    def save_hold_invoice(self, invoice: HoldInvoice) -> None:
        """Saves a hold invoice to the db"""
        self._hold_invoices[invoice.payment_hash.hex()] = invoice
        self._db.write()

    def delete_hold_invoice(self, payment_hash: Union[bytes, str], write_db: bool = True) -> None:
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        self._logger.debug(f"delete_hold_invoice: {payment_hash}")
        self.unregister_hold_invoice_callback(payment_hash)
        res = self._hold_invoices.pop(payment_hash, None)
        if res is None:
            return
        # issue #25: tombstone the hash so replayed/late HTLCs for this
        # deleted hold fail instead of parking (persisted via db dict)
        self._tombstones[payment_hash] = True
        # Issue #3: if this was a bundled prepay, drop the reverse index
        self._bundle_main_of.pop(payment_hash, None)
        if write_db:
            self._db.write()

    def b11invoice_from_hash(self, *,
            payment_hash: Union[str, bytes],
            amount_msat: int,
            message: Optional[str] = "",
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str] = None,
            min_final_cltv_expiry_delta: Optional[int] = None,
            store_invoice: bool = True) -> HoldInvoice:
        assert amount_msat > 0, f"b11invoice_from_hash: amount_msat must be > 0, but got {amount_msat}"
        if isinstance(payment_hash, str):
            payment_hash = bytes.fromhex(payment_hash)
        if len(payment_hash) != 32:
            raise InvalidInvoiceCreationError("b11invoice_from_hash: payment_hash "
                                              "must be 32 bytes, was " + str(len(payment_hash)))
        if len(self._rpc.listinvoices(payment_hash=payment_hash.hex())["invoices"]) > 0:
            raise DuplicateInvoiceCreationError("b11invoice_from_hash: "
                                                "invoice already exists in cln: " + payment_hash.hex())

        # Quotes below verified against lightning/bolts by greatspectations
        # (specquotes.toml; tests/test_spec_quotes.py gates this in pytest).
        # BOLT #11: A writer:
        #  - MUST include exactly one `p` field.
        #  - MUST include exactly one `s` field.
        #  - MUST set `payment_hash` to the SHA2 256-bit hash of the `payment_preimage`
        #  that will be given in return for payment.
        # Impl-note: the preimage lives with the CLIENT for normal swaps (they
        # Impl-note: reveal it by spending the onchain HTLC); we only ever see
        # Impl-note: the hash, so the hold invoice settles from the claim tx's
        # Impl-note: witness, never here.
        # BOLT #11: SHOULD include one `c` field (`min_final_cltv_expiry_delta`).
        #  - MUST set `c` to the minimum `cltv_expiry` it will accept for the last
        #  HTLC in the route.
        invoice_features = LnFeatures(0) | LnFeatures.VAR_ONION_REQ | LnFeatures.PAYMENT_SECRET_REQ | LnFeatures.BASIC_MPP_OPT
        routing_hints = self._get_route_hints(amount_msat)
        lnaddr = LnAddr(
            net=self._config.network,
            paymenthash=payment_hash,
            amount=Decimal(amount_msat) / Decimal(COIN*1000),
            tags=[
                     ('c', MIN_FINAL_CLTV_DELTA_FOR_INVOICE if min_final_cltv_expiry_delta is None
                                                                else min_final_cltv_expiry_delta),
                     ('d', message if message and len(message) > 0 else f"swap {datetime.now()}"),
                     ('x', LN_EXPIRY_NEVER if expiry == 0 else expiry),
                     ('9', invoice_features),
                     ('f', fallback_address),
                 ] + routing_hints,
            date=int(time.time()),
            payment_secret=self._get_payment_secret(payment_hash))
        b11invoice_unsigned: str = lnencode_unsigned(lnaddr)
        try:
             self._logger.debug(f"b11invoice_from_hash: unsigned invoice: {b11invoice_unsigned}")
             signed = self._rpc.call(
                 "signinvoice",
                 {
                     "invstring": b11invoice_unsigned,
                 },
             )["bolt11"]
             self._logger.debug(f"b11invoice_from_hash: signed invoice: {signed}")
        except Exception as e:
            self._logger.error(f"b11invoice_from_hash: signinvoice rpc failed: {e}")
            raise Bolt11InvoiceCreationError("signinvoice rpc failed: " + str(e))
        invoice = HoldInvoice(payment_hash, signed, amount_msat, expiry)
        if store_invoice:
            self.save_hold_invoice(invoice)
        return invoice

    def _get_route_hints(self, amount_msat: int) -> List[Tuple[str, List[Tuple[bytes, ShortID, int, int, int]]]]:
        # BOLT #11: if there is NOT a public channel associated with its public key:
        #  - MUST include at least one `r` field.
        #  - `r` field MUST contain one or more ordered entries, indicating the forward route from
        #  a public node to the final destination.
        # Impl-note: we deliberately hint PUBLIC channels too. The BOLT only
        # Impl-note: mandates hints for private routes, but payers with
        # Impl-note: lagging/partial gossip maps (fresh channels sit ~20-40
        # Impl-note: blocks behind gossip) raise NoPathFound when the invoice
        # Impl-note: carries zero hints — observed live on signet 2026-08-20
        # Impl-note: (commit 35cab8c).
        if amount_msat is None or amount_msat == 0:
            raise NotImplementedError  # swaps always have the amount defined
        try:
            available_channels = self._rpc.listpeerchannels()["channels"]
        except Exception as e:
            # #21 contract 2: an RPC failure must not silently produce a
            # hint-less invoice that is unroutable on private-channel nodes
            self._logger.error(f"_get_route_hints rpc failed: {e}")
            raise RouteHintUnavailableError(f"cannot probe channels for route hints: {e}") from e

        suitable_channels = filter_suitable_recv_chans(amount_msat,
                                                            available_channels)
        routing_hints = []
        for channel in suitable_channels:
            # a NORMAL channel whose gossip exchange has not completed yet
            # (fresh channel + just-reconnected peer) carries no
            # updates.remote — hinting from it crashes the whole swap
            # creation with KeyError (earned live on the regtest lab
            # 2026-08-29: every createswap died on a 1-block-old channel
            # whose remote channel_update never arrived). Skip instead —
            # a hint-less-but-healthy sibling channel still covers the
            # R9 case; if none do, the payer's NoPathFound surfaces.
            updates = (channel.get("updates") or {}).get("remote")
            if not updates:
                self._logger.warning(
                    f"_get_route_hints: skipping channel "
                    f"{channel.get('short_channel_id')} (no remote updates — "
                    "gossip exchange incomplete)")
                continue
            short_id = ShortID.from_str(channel["short_channel_id"])
            routing_hints.append(('r', [(
                bytes.fromhex(channel["peer_id"]),
                short_id,
                int(channel["updates"]["remote"]["fee_base_msat"]),
                int(channel["updates"]["remote"]["fee_proportional_millionths"]),
                int(channel["updates"]["remote"]["cltv_expiry_delta"]))]))

        if not routing_hints:
            # #53 (hunter-2, the R9 inversion): RPC-OK with zero usable
            # channels used to fall through and EMIT a hint-less invoice
            # — unroutable paper pushed onto the payer. Refuse; the
            # caller turns this into a typed error reply.
            raise RouteHintUnavailableError(
                f"no suitable channels for route hint "
                f"(0 of {len(available_channels)} channels usable)")
        return routing_hints

    def _get_payment_secret(self, payment_hash: Union[str, bytes]) -> bytes:
        if isinstance(payment_hash, str):
            payment_hash = bytes.fromhex(payment_hash)
        assert len(payment_hash) == 32, f"_get_payment_secret: payment_hash must be 32 bytes, was {len(payment_hash)}"
        return sha256(sha256(self._payment_secret_key) + payment_hash)

    def bundle_payments(self, *, swap_invoice: HoldInvoice, prepay_invoice: HoldInvoice) -> None:
        current_invoice = self.get_hold_invoice(swap_invoice.payment_hash)
        # remove the old invoice so changes are tracked by the JsonDB StoredDict
        self._hold_invoices.pop(swap_invoice.payment_hash.hex())
        current_invoice.attach_prepay_invoice(prepay_invoice.payment_hash)
        # Issue #3: remember which main this prepay belongs to (persisted),
        # so expiring the prepay can cancel the main instead of letting the
        # callback fire without the prepay (R4/F8 coupling).
        self._bundle_main_of[prepay_invoice.payment_hash.hex()] = swap_invoice.payment_hash.hex()
        # then store the updated invoice with the prepay invoice attached
        self.save_hold_invoice(current_invoice)

    def get_preimage(self, payment_hash: Union[bytes, str]) -> Optional[str]:
        if isinstance(payment_hash, str):
            payment_hash = bytes.fromhex(payment_hash)
        assert len(payment_hash) == 32, f"get_preimage: payment_hash must be 32 bytes, was {len(payment_hash)}"
        preimage_hex = self._preimages.get(payment_hash.hex())
        if preimage_hex is None:
            return None
        if sha256(bytes.fromhex(preimage_hex)) != payment_hash:
            raise InvalidPreimageFoundError("found incorrect preimage for payment_hash")
        return preimage_hex

    def is_tombstoned(self, payment_hash: Union[bytes, str]) -> bool:
        """#81 §1.4-3 (2026-08-31): True if this hash was ever committed
        to a hold invoice that has since been deleted (completed,
        expired, or cancelled). A completed d1 swap's preimage is PUBLIC
        (published in the claim-tx witness) and its hash never enters
        _preimages (client-held, only extracted into the swap record
        before that record de-indexes) — the tombstone set is the only
        persisted memory that the hash is spent."""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        return payment_hash in self._tombstones

    def num_sats_can_receive(self) -> int:
        """returns max inbound capacity; raises CapacityProbeError on RPC
        failure (#21 contract 1) so callers can distinguish outage from
        actual zero capacity."""
        inbound_capacity_sat = 0
        try:
            available_channels = self._rpc.listfunds()["channels"]
        except Exception as e:
            raise CapacityProbeError(f"listfunds rpc failed: {e}") from e
        for channel in available_channels:
            if channel["connected"]:
                inbound_capacity_sat += (channel["amount_msat"] - channel["our_amount_msat"]) / 1000
        return int(inbound_capacity_sat * self.INBOUND_LIQUIDITY_FACTOR)

    def num_sats_can_send(self) -> int:
        """returns max outbound capacity; raises CapacityProbeError on RPC
        failure (#21 contract 1)."""
        outbound_capacity_sat = 0
        try:
            available_channels = self._rpc.listfunds()["channels"]
        except Exception as e:
            raise CapacityProbeError(f"listfunds rpc failed: {e}") from e
        for channel in available_channels:
            if channel["connected"]:
                outbound_capacity_sat += channel["our_amount_msat"] / 1000
        return int(outbound_capacity_sat * self.INBOUND_LIQUIDITY_FACTOR)


class InvalidInvoiceCreationError(Exception):
    pass

class InvalidPreimageFoundError(Exception):
    pass

class ClnRpcError(Exception):
    pass

class InvalidPreimageSavedError(Exception):
    pass

class CapacityProbeError(Exception):
    """#21 contract 1: RPC failure during capacity probing — the server
    must not present an outage as an exhausted-wallet business answer."""
    pass

class RouteHintUnavailableError(Exception):
    """#21 contract 2: route hints cannot be built (RPC failure) and the
    node has private channels — issuing a hint-less invoice would be
    unroutable; refuse instead."""
    pass

class Bolt11InvoiceCreationError(Exception):
    pass

class InvoiceNotFoundError(Exception):
    pass
