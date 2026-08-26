# annotations stay unevaluated so CLN-bound types (TYPE_CHECKING-only
# imports below) can appear in signatures without pyln at import time
from __future__ import annotations
import asyncio

from .jit_channel import (
    is_no_route_failure, decode_payee_node, has_channel_to,
    open_jit_channel, wait_channel_lockin, jit_enabled, jit_liquidity_factor,
)
import traceback

import attr
import json
import os
import math
import time

from decimal import Decimal
from typing import Optional, Dict, Tuple, Union
import electrum_aionostr as aionostr
from electrum_ecc import ECPrivkey


class RequestFieldError(Exception):
    """Client sent a malformed field; maps to a clean error REPLY."""


# Issue #4 / BOLT #11 reader MUSTs, enforced at the ACTION BOUNDARY —
# electrum's architecture (bolt11 decode is deliberately lenient so old
# stored invoices stay parseable; lnworker._check_bolt11_invoice +
# validate_features enforce before paying). Even bits an invoice may
# REQUIRE of us as payer; unknown even bits → reject (electrum
# validate_features semantics). Odd/optional bits are ignorable per spec.
INVOICE_SUPPORTED_EVEN_BITS = {8, 14, 16, 18}  # var_onion, payment_secret, basic_mpp, large_channel


def check_invoice_before_payment(bolt11_invoice: str):
    """BOLT #11 reader MUSTs before we accept a client invoice (issue #4).

    Fails at the API boundary with RequestFieldError — never after the
    client's onchain lockup. Returns the decoded LnAddr."""
    from .lnaddr import lndecode, LnDecodeException
    try:
        addr = lndecode(bolt11_invoice)
    except LnDecodeException as e:
        raise RequestFieldError(f'invoice is not valid bolt11: {e}')
    # BOLT #11: - MUST fail the payment if any field with fixed `data_length` (`p`, `h`, `s`, `n`) does not have the correct length (52, 52, 52, 53).
# Impl-note: (lenient decode routes malformed tags to unknown_tags /
# Impl-note: leaves the field unset — we check the unset field)
    if addr.paymenthash is None:
        raise RequestFieldError('invoice has no valid payment hash (p tag)')
    # BOLT #11: - MUST fail the payment if neither a `d` field nor a `h`
    #  field is present, or if both are present.
    has_d, has_h = addr.get_tag('d') is not None, addr.get_tag('h') is not None
    if has_d and has_h:
        raise RequestFieldError('invoice has both d and h tags')
    if not has_d and not has_h:
        raise RequestFieldError('invoice has neither d nor h tag')
    # BOLT #11: - if a valid `s` field is not provided:
    #  - MUST fail the payment.
    if addr.payment_secret is None:
        raise RequestFieldError('invoice has no payment secret (s tag)')
    # BOLT #11: - if the `9` field contains unknown _even_ bits that are non-zero:
    #  - MUST fail the payment.
# Impl-note: (unknown odd bits are ignorable per the same section)
    features = addr.get_tag('9') or 0
    if features.bit_length() > 10_000:
        raise RequestFieldError(f'invoice feature vector too large '
                                f'({features.bit_length()} bits)')
    for fbit in range(features.bit_length()):
        if features >> fbit & 1 and fbit % 2 == 0 and fbit not in INVOICE_SUPPORTED_EVEN_BITS:
            raise RequestFieldError(f'invoice requires unknown/unsupported '
                                    f'feature bit {fbit}')
    return addr


from electrum_aionostr.util import to_nip19
from collections import defaultdict

from .bitcoin import opcodes, dust_threshold, construct_script, script_to_p2wsh, construct_witness
from .transaction import (PartialTxOutput, PartialTransaction, TxOutpoint, Transaction,
                          OPPushDataGeneric, OPPushDataPubkey, PartialTxInput)
from .utils import (OldTaskGroup, now, BelowDustLimit, TxBroadcastError,
                    ignore_exceptions, log_exceptions, supervise)
from .bitcoin import DummyAddress
from .crypto import ripemd, sha256
from .health import tracker
from .lnutil import hex_to_bytes, REDEEM_AFTER_DOUBLE_SPENT_DELAY, bytes_to_hex
from .invoices import Invoice, InvoiceState
from .json_db import StoredObject, stored_in, JsonDB
from . import constants
from .constants import (MIN_LOCKTIME_DELTA, LOCKTIME_DELTA_REFUND, MAX_LOCKTIME_DELTA,
                        MIN_FINAL_CLTV_DELTA_FOR_CLIENT, CLAIM_FEE_SIZE, LOCKUP_FEE_SIZE,
                        MIN_FINAL_CLTV_DELTA_ACCEPTED, MIN_FINAL_CLTV_DELTA_FOR_INVOICE,
                        PAYMENT_INFLIGHT_LOCK, FUNDING_GATE_TIMEOUT_BLOCKS_DEFAULT,
                        FUNDING_GATE_POLL_SECONDS, INVOICE_EXPIRY_SECONDS_DEFAULT)
# CLN-bound collaborators are import-time-free so the protocol/wire logic
# (swap scripts, offers, fee math) stays testable without a node — the
# cln_* classes only appear in annotations; InvoiceNotFoundError is
# imported at its single raise site.
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .cln_chain import CLNChainWallet
    from .cln_lightning import CLNLightning
    from .chain_monitor import ChainMonitor
from .plugin_config import PluginConfig
from .cln_logger import PluginLogger


# REVERSE SWAPS:
#         - User generates preimage, RHASH. Sends RHASH to server.
#         - Server creates an LN invoice for RHASH.
#         - User pays LN invoice - except server needs to hold the HTLC as preimage is unknown.
#             - if the server requested a fee prepayment (using 'minerFeeInvoice'),
#               the server will have the preimage for that. The user will send HTLCs for both the main RHASH,
#               and for the fee prepayment. Once both MPP sets arrive at the server, the server will fulfill
#               the HTLCs for the fee prepayment (before creating the on-chain output).
#         - Server creates on-chain output locked to RHASH.
#         - User spends on-chain output, revealing preimage.
#         - Server fulfills HTLC using preimage.

# The script of the reverse swaps has one extra check in it to verify
# that the length of the preimage is 32. This is required because in
# the reverse swaps the preimage is generated by the user and to
# settle the hold invoice, you need a preimage with 32 bytes . If that
# check wasn't there the user could generate a preimage with a
# different length which would still allow for claiming the onchain
# coins but the invoice couldn't be settled

WITNESS_TEMPLATE_REVERSE_SWAP = [
     opcodes.OP_SIZE,
     OPPushDataGeneric(None),
     opcodes.OP_EQUAL,
     opcodes.OP_IF,
     opcodes.OP_HASH160,
     OPPushDataGeneric(lambda x: x == 20),
     opcodes.OP_EQUALVERIFY,
     OPPushDataPubkey,
     opcodes.OP_ELSE,
     opcodes.OP_DROP,
     OPPushDataGeneric(None),
     opcodes.OP_CHECKLOCKTIMEVERIFY,
     opcodes.OP_DROP,
     OPPushDataPubkey,
     opcodes.OP_ENDIF,
     opcodes.OP_CHECKSIG
 ]

@stored_in('submarine_swaps')
@attr.s
class SwapData(StoredObject):
    is_reverse = attr.ib(type=bool)  # for whoever is running code (PoV of client or server)
    locktime = attr.ib(type=int)
    onchain_amount = attr.ib(type=int)  # in sats
    lightning_amount = attr.ib(type=int)  # in sats
    redeem_script = attr.ib(type=str, converter=bytes_to_hex)
    preimage = attr.ib(type=Optional[str], converter=bytes_to_hex)
    prepay_hash = attr.ib(type=Optional[str], converter=bytes_to_hex)
    privkey = attr.ib(type=str, converter=bytes_to_hex)
    lockup_address = attr.ib(type=str)
    receive_address = attr.ib(type=str)
    funding_txid = attr.ib(type=Optional[str])
    spending_txid = attr.ib(type=Optional[str])
    is_redeemed = attr.ib(type=bool)
    # issue #15 (production lineage ebed8ff): persisted marker that the
    # client completed addswapinvoice REGISTRATION — an onchain_to_ln
    # lockup may only be claimed after registration; an abandoned
    # (funded, never registered) lockup stays refundable to the
    # client's key. Production jsondb records carry this field — it
    # MUST stay in the schema (records with `registered` crashed older
    # builds on load). The gate survives restarts; in the audit-round7
    # lineage the gate itself is the sweep-grace window (issue #10
    # option B): refundable until locktime + SWEEP_GRACE_BLOCKS, then
    # swept under the ERROR-level policy log.
    registered = attr.ib(type=bool, default=False)

    _funding_prevout = None  # type: Optional[TxOutpoint]  # for RBF
    _payment_hash = None

    @property
    def payment_hash(self) -> bytes:
        return hex_to_bytes(self._payment_hash)


def create_claim_tx(
        *,
        txin: PartialTxInput,
        witness_script: Union[str, bytes],
        address: str,
        amount_sat: int,
        locktime: int,
) -> PartialTransaction:
    """Create tx to either claim successful reverse-swap,
    or to get refunded for timed-out forward-swap.
    """
    if isinstance(witness_script, str):
        witness_script = hex_to_bytes(witness_script)
    txin.script_sig = b''
    txin.witness_script = witness_script
    txout = PartialTxOutput.from_address_and_value(address, amount_sat)
    tx = PartialTransaction.from_io([txin], [txout], version=2, locktime=locktime)
    tx.set_rbf(True)
    return tx


class SwapManager:

    def __init__(self, *, wallet: CLNChainWallet, lnworker: CLNLightning,
                 db: JsonDB, plugin_config: PluginConfig, logger: PluginLogger, chain_monitor: ChainMonitor):
        self.logger = logger
        self.normal_fee = None
        self.lockup_fee = None
        self.claim_fee = None  # part of the boltz prococol, not used by Electrum
        self.percentage = None
        self._min_amount = None
        self._max_amount = None

        self.wallet = wallet
        self.lnworker = lnworker
        self.lnwatcher = chain_monitor
        self.db = db
        self.dummy_address = DummyAddress.SWAP
        self.config = plugin_config
        self.taskgroup = OldTaskGroup()

        self.swaps = self.db.get_dict('submarine_swaps')  # type: Dict[str, SwapData]
        # issues #18/#22 (audit F04/F21): damaged swap state is never
        # silently deleted at startup — it is MOVED here (reason + full
        # record persisted, ERROR-logged) and left unprocessed
        self.quarantined_swaps = self.db.get_dict('quarantined_swaps')
        self._swaps_by_funding_outpoint = {}  # type: Dict[TxOutpoint, SwapData]
        self._swaps_by_lockup_address = {}  # type: Dict[str, SwapData]
        for payment_hash_hex in list(self.swaps.keys()):
            swap = self.swaps[payment_hash_hex]
            swap._payment_hash = payment_hash_hex
            # issue #22 (audit F21): refuse-loudly load integrity — a
            # record missing the key material for its direction can
            # never be refunded or claimed; quarantine, never process
            reasons = self._swap_integrity_errors(payment_hash_hex, swap)
            if not reasons and not swap.is_reverse and not swap.is_redeemed:
                if self.lnworker.get_hold_invoice(payment_hash_hex) is None:
                    # issue #18 (audit F04): used to be a SILENT
                    # self.swaps.pop() — persistent state deleted on an
                    # inference, with a funded lockup losing both its
                    # record and (via main_loop's re-add) its chain
                    # watcher. Quarantine + ERROR instead; the payer
                    # keeps CLN's HTLC timeouts, the operator keeps the
                    # evidence.
                    reasons = ['hold invoice missing at startup (expired, '
                               'or hold_invoices section damaged — audit F04)']
            if reasons:
                self._quarantine_swap(payment_hash_hex, swap, reasons)
                continue
            payment_hash = bytes.fromhex(payment_hash_hex)
            self._add_or_reindex_swap(swap)
            if not swap.is_reverse and not swap.is_redeemed:
                self.lnworker.register_hold_invoice_callback(payment_hash=payment_hash,
                                                             callback=self.hold_invoice_callback)

        self.prepayments = {}  # type: Dict[bytes, bytes] # fee_rhash -> rhash
        for k, swap in self.swaps.items():
            if swap.prepay_hash is not None:
                self.prepayments[swap.prepay_hash] = bytes.fromhex(k)
        self.assert_constants()
        self._load_integrity_scan()
        self.is_server = True  # this plugin is always a server
        self.use_nostr = True  # this plugin only uses nostr comm
        self.is_initialized = asyncio.Event()  # set once nostr is connected to relays
        # d2 invoices parked at addswapinvoice until the lockup is seen
        # onchain (issue #12); memory-only like invoices_to_pay — clients
        # re-send addswapinvoice after a restart
        self.invoices_awaiting_funding = set()
        # issue #24 option E: absolute block height at which a parked
        # invoice's M-block funding-gate window ends (anchored on the
        # first watch pass at/after addswapinvoice; None-pending values
        # are resolved there). Memory-only, same restart contract as
        # invoices_awaiting_funding.
        self._funding_gate_deadline = {}  # type: Dict[str, Optional[int]]
        # issue #10: swap ids that already produced their grace-hold /
        # grace-release log line (log-once discipline); memory-only
        self._grace_hold_logged = set()
        self._grace_release_logged = set()

    @staticmethod
    def _swap_integrity_errors(payment_hash_hex: str, swap: SwapData) -> list:
        """Issue #22 (audit F21) load-integrity: the key material the
        claim/refund paths need. privkey + redeem_script are required in
        BOTH directions (refund for forward, claim for reverse). preimage
        is Optional by design in both — the client holds it for forwards,
        it is extracted from the spending tx for reverses — but WHEN
        present it must hash to the record's payment_hash (a mismatch
        means fields from different records were merged)."""
        errors = []
        try:
            payment_hash = bytes.fromhex(payment_hash_hex)
            if len(payment_hash) != 32:
                raise ValueError('not 32 bytes')
        except ValueError:
            errors.append('payment_hash key is not valid 32-byte hex')
            payment_hash = None
        for field in ('privkey', 'redeem_script'):
            value = getattr(swap, field, None)
            try:
                raw = hex_to_bytes(value) if value else None
                if not raw:
                    raise ValueError('missing')
                if field == 'privkey' and len(raw) != 32:
                    raise ValueError(f'{len(raw)} bytes, need 32')
            except (ValueError, TypeError):
                errors.append(f'{field} missing/unparsable')
        if swap.preimage and payment_hash is not None \
                and sha256(hex_to_bytes(swap.preimage)) != payment_hash:
            errors.append('preimage does not hash to payment_hash')
        return errors

    def _quarantine_swap(self, payment_hash_hex: str, swap: SwapData,
                         reasons: list) -> None:
        """Issues #18/#22 (audit F04/F21): startup refuse-loudly — the
        damaged record is MOVED to the persisted 'quarantined_swaps' db
        section (reason + full record), ERROR-logged with the payment
        hash, and never processed (no chain watcher, no hold callback,
        no payment). Restoring it is an explicit operator action."""
        reason = '; '.join(reasons)
        self.quarantined_swaps[payment_hash_hex] = {
            'reason': reason,
            'quarantined_at': now(),
            'swap': swap.to_json(),
        }
        self.swaps.pop(payment_hash_hex, None)
        self.logger.error(
            f"quarantined swap {payment_hash_hex}: {reason} — record "
            f"preserved in db section 'quarantined_swaps', will not be "
            f"processed")
        self.db.write()

    def _load_integrity_scan(self) -> None:
        """Issues #18/#22 (audit R3/F21): cheap consistency scan at db
        load — every swap carries lockup_address + locktime (WARN only),
        payment entries (invoices / lightning_preimages) reference known
        payment hashes (orphans WARN — never deleted), counts logged at
        INFO. The snapshot feeds swapprovider-health's last_load_integrity."""
        swap_keys = set(self.swaps.keys())
        structural_warns = []
        for key, swap in self.swaps.items():
            missing = [f for f in ('lockup_address', 'locktime')
                       if not getattr(swap, f, None)]
            if missing:
                structural_warns.append(f"swap {key[:12]}… missing "
                                        f"{','.join(missing)}")
        orphans = []
        for section in ('_invoices', '_preimages'):
            entries = getattr(self.lnworker, section, None) or {}
            orphans += [f"{k[:12]}… ({section})" for k in entries
                        if k not in swap_keys]
        for w in structural_warns:
            self.logger.warning(f"load-integrity: {w}")
        for o in orphans:
            self.logger.warning(f"load-integrity: orphan payment entry {o} "
                                f"(no matching swap record — kept, not deleted)")
        self.load_integrity = {
            'swaps': len(self.swaps),
            'quarantined': len(self.quarantined_swaps),
            'orphans': len(orphans),
            'missing_lockup_or_locktime': len(structural_warns),
        }
        self.logger.info(f"datastore loaded: {self.load_integrity['swaps']} "
                         f"swaps, {self.load_integrity['quarantined']} "
                         f"quarantined, {self.load_integrity['orphans']} "
                         f"orphan payments")

    @log_exceptions
    async def run_nostr_server(self):
        while True:
            try:
                with NostrTransport(config=self.config, sm=self) as transport:
                    # issue #17: a transport that dies BEFORE connecting
                    # (relay_manager.connect raising) used to wedge the
                    # is_connected wait forever — race the handshake
                    # against the dead flag
                    conn = asyncio.create_task(transport.is_connected.wait())
                    death = asyncio.create_task(transport.dead.wait())
                    await asyncio.wait({conn, death},
                                       return_when=asyncio.FIRST_COMPLETED)
                    for t in (conn, death):
                        t.cancel()
                    if not transport.is_connected.is_set():
                        # issue #20: dead on arrival — withdraw (no offer,
                        # is_initialized stays clear so requests are
                        # refused) and let the outer loop rebuild after 15s
                        self.logger.error('nostr transport died before connecting — '
                                          'withdrawing offer, refusing new swap requests')
                        tracker.note_nostr_down('died before connecting')
                    else:
                        self.logger.info(f'nostr is connected')
                        tracker.note_nostr_up()
                    last_advertised_max = None
                    while transport.is_connected.is_set() and not transport.dead.is_set():
                        # todo: publish everytime fees have changed
                        self.server_update_pairs()
                        # issue #20 (audit F06): bound the announce. A relay
                        # that went away makes aionostr's send/reconnect
                        # block for its full quadratic retry schedule —
                        # without the bound this loop (and the offer) would
                        # freeze silently instead of withdrawing. On
                        # failure: withdraw the offer, refuse new swaps,
                        # retry on the fast cadence below.
                        try:
                            await asyncio.wait_for(transport.publish_offer(), timeout=60)
                            tracker.note_success('offer-publisher')
                        except Exception:
                            self.logger.error(f'publishing offer failed — withdrawing offer, '
                                              f'refusing new swap requests:\n'
                                              f'{traceback.format_exc()}')
                            self.is_initialized.clear()
                            tracker.note_error('offer-publisher', detail='publish failed')
                            tracker.note_nostr_down('publish failed')
                        tracker.beat('offer-publisher',
                                     detail='withdrawn, retrying' if not self.is_initialized.is_set()
                                     else 'published')
                        if not self.is_initialized.is_set():  # if publish offer didn't set initialized we retry faster
                            await asyncio.sleep(10)
                            continue
                        # converge fast while caps still move: the first
                        # pass after a restart races peer reconnection and
                        # advertises the 20k floor; recompute on a short
                        # cadence until the advertised cap stabilizes
                        if last_advertised_max != self._max_amount:
                            last_advertised_max = self._max_amount
                            cadence = 30
                        else:
                            cadence = 600
                        # issue #20: wake early if the DM consumer dies —
                        # withdraw immediately instead of announcing into a
                        # dead request pipeline for the rest of the cadence
                        try:
                            await asyncio.wait_for(transport.dead.wait(), timeout=cadence)
                        except asyncio.TimeoutError:
                            pass  # normal cadence expiry
                        if transport.dead.is_set():
                            self.logger.error('nostr DM consumer died — withdrawing offer '
                                              '(no further kind-30315 republishes) and '
                                              'refusing new swap requests until the '
                                              'transport restarts')
                            self.is_initialized.clear()
                            tracker.note_nostr_down('DM consumer died')
                            break
            except asyncio.TimeoutError:
                self.logger.warning(f"Nostr timeout, restarting Nostr module")
            await asyncio.sleep(15)

    async def main_loop(self):
        if self.is_initialized.is_set():
            raise Exception("swap manager main_loop called twice, already running")
        # re-register persisted swaps' lockup addresses into the bitcoind
        # wallet (imports are lost on wallet restart/recreate; without
        # this, _claim_swap hits UnknownAddressError every block)
        for k, swap in self.swaps.items():
            if swap.is_redeemed:
                continue
            await self.lnwatcher.register_address(swap.lockup_address)
            self.add_lnwatcher_callback(swap)
            # #28: re-register the hold-invoice callback too — the dict
            # starts empty each process, so a FUNDED hold parked before a
            # restart never fired its funding callback afterward (the
            # payer's HTLC sat parked until the #28 watchdog or CLTV).
            # Only ln_to_onchain (is_reverse server-side) holds carry a
            # funding obligation; registered==False means phase-2 never
            # bound an invoice — nothing to fund, skip (firing the
            # callback for it would just hit the no-swap guard).
            if not swap.is_reverse and swap.registered and swap.funding_txid is None:
                self.lnworker.register_hold_invoice_callback(
                    payment_hash=swap.payment_hash, callback=self.hold_invoice_callback)

        tasks = [
                    self.lnwatcher.trigger_callbacks(),  # trigger all callbacks once
                    self.pay_pending_ln_invoices(),
                    self.funding_gate_watch_loop(),
                    self.run_nostr_server()
                ]

        async with self.taskgroup as group:
            for task in tasks:
                t = await group.spawn(task)
                # issue #17: log unobserved deaths at ERROR. Death policy
                # for these core loops: FATAL by escalation — the
                # OldTaskGroup propagates a child death through join,
                # which ends run() and hits the #16 crash policy (log +
                # hard exit). Visible death beats an invisible half-life;
                # lightningd's restart is the recovery.
                supervise(t, logger=self.logger, name=task.__name__)

    async def stop(self):
        self.logger.debug("SwapManager stop() called")
        await self.taskgroup.cancel_remaining()

    def assert_constants(self):
        assert MIN_LOCKTIME_DELTA <= LOCKTIME_DELTA_REFUND <= MAX_LOCKTIME_DELTA, \
            f"assert failed: {MIN_LOCKTIME_DELTA} <= {LOCKTIME_DELTA_REFUND} <= {MAX_LOCKTIME_DELTA}"
        assert MAX_LOCKTIME_DELTA < MIN_FINAL_CLTV_DELTA_ACCEPTED, \
            f"assert failed: {MAX_LOCKTIME_DELTA} < {MIN_FINAL_CLTV_DELTA_ACCEPTED}"
        assert MAX_LOCKTIME_DELTA < MIN_FINAL_CLTV_DELTA_FOR_INVOICE, \
            f"assert failed: {MAX_LOCKTIME_DELTA} < {MIN_FINAL_CLTV_DELTA_FOR_INVOICE}"
        assert MAX_LOCKTIME_DELTA < MIN_FINAL_CLTV_DELTA_FOR_CLIENT, \
            f"assert failed: {MAX_LOCKTIME_DELTA} < {MIN_FINAL_CLTV_DELTA_FOR_CLIENT}"

    async def pay_pending_ln_invoice(self, key):
        self.logger.debug(f'trying to pay invoice {key}')
        # attempt cap: an unpayable invoice (e.g. onchain_to_ln bind whose hints the
        # payer can't route — alias-scid mismatch) must not retry forever.
        # Earned live: one invoice retried every 60s for 2.5h+, spamming
        # logs and pinning the swap. 15 attempts then fail the swap.
        if (n := self._invoice_attempts.setdefault(key, 0) + 1) > 15:
            self.logger.warning(f'giving up on invoice {key} after {n - 1} '
                                'attempts (unpayable)')
            self._invoice_attempts.pop(key, None)
            self._fail_swap(self.swaps.get(key, None),
                            'invoice unpayable after 15 attempts')
            self.invoices_to_pay.pop(key, None)
            return
        self._invoice_attempts[key] = n
        self.invoices_to_pay[key] = PAYMENT_INFLIGHT_LOCK  # marks the attempt in flight
        try:
            if (invoice := self.lnworker.get_invoice(key)) is None:
                from .cln_lightning import InvoiceNotFoundError
                raise InvoiceNotFoundError()
            success, log = await self.lnworker.pay_invoice(bolt11=invoice.lightning_invoice, attempts=5)
        except Exception:
            self.logger.error(f'exception paying {key}: {traceback.format_exc()}, will not retry')
            self._fail_swap(self.swaps.get(key, None), 'exception paying invoice')
            return
        if not success:
            if invoice.has_expired():
                self._fail_swap(self.swaps.get(key, None), f'reverse swap invoice expired, '
                                                           f'not trying to pay it again: {log}')
                return
            # JIT channel (LSP model): when the failure is specifically
            # 'no route to payee', open a channel to the payee and retry
            # through it — the CLTV window (70 blocks) provides plenty of
            # time. Falls through to normal retry if the JIT open fails.
            if is_no_route_failure(log) and jit_enabled(self.lnworker._rpc):
                payee = decode_payee_node(
                    invoice.lightning_invoice, self.lnworker._rpc)
                if payee and not has_channel_to(payee, self.lnworker._rpc):
                    amt_sat = int(getattr(invoice, 'amount_msat', 0)) // 1000 or 20_000
                    factor = jit_liquidity_factor(self.lnworker._rpc)
                    self.logger.info(
                        f'jit: no route to {payee[:12]}… — opening '
                        f'channel (invoice ~{amt_sat}sat, liquidity '
                        f'{factor:.0%})')
                    opened = open_jit_channel(
                        payee, amt_sat, self.lnworker._rpc,
                        liquidity_factor=factor)
                    if opened and wait_channel_lockin(
                            payee, self.lnworker._rpc):
                        self.invoices_to_pay[key] = now() + 5
                        self.logger.info(
                            f'jit: retrying {key[:8]}… via new channel')
                        return
            self.logger.warning(f'failed to pay pending invoice {key}: {log}, will retry in 1 minute')
            self.invoices_to_pay[key] = now() + 60
        else:
            self.logger.info(f'paid invoice {key}')
            tracker.note_success('payment-loop')
            self._invoice_attempts.pop(key, None)
            self.lnworker.delete_invoice(key)
            self.invoices_to_pay.pop(key, None)

    async def pay_pending_ln_invoices(self):
        self.invoices_to_pay = {}
        self._invoice_attempts = {}
        while True:
            await asyncio.sleep(5)
            tracker.beat('payment-loop',
                         detail=f'{len(self.invoices_to_pay)} tracked')
            for key, not_before in list(self.invoices_to_pay.items()):
                if now() < not_before:
                    continue
                await self.taskgroup.spawn(self._supervised_pay_invoice(key))

    async def _supervised_pay_invoice(self, key):
        """Issue #17 payment-loop death policy: RECOVERABLE. A bug in ONE
        payment attempt must not kill the taskgroup (and with it every
        subsystem — the OldTaskGroup escalates child deaths fatally).
        pay_pending_ln_invoice handles its own failure paths; whatever
        escapes it is logged at ERROR here and the invoice lock is
        re-queued with backoff — the 15-attempt cap in
        pay_pending_ln_invoice still bounds total retries."""
        try:
            await self.pay_pending_ln_invoice(key)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.error(f'payment task for {key} died unexpectedly:\n'
                              f'{traceback.format_exc()}')
            tracker.note_error('payment-loop', detail=f'task death {key[:8]}…')
            if self.invoices_to_pay.get(key) == PAYMENT_INFLIGHT_LOCK:
                self.invoices_to_pay[key] = now() + 60

    def _fail_swap(self, swap: SwapData, reason: str):
        if swap is None:
            return
        self.logger.warning(f'failing swap {swap.payment_hash.hex()}: {reason}')
        if not swap.is_reverse and swap.payment_hash in self.lnworker._hold_invoice_callbacks:
            self.lnworker.unregister_hold_invoice_callback(swap.payment_hash)
            for payment_hash in [swap.payment_hash, swap.prepay_hash]:
                # prepay hash should already be settled at this point
                invoice = self.lnworker.get_hold_invoice(payment_hash)
                if invoice:
                    invoice.cancel_all_htlcs()
                    self.lnworker.delete_hold_invoice(payment_hash, False)
                self.lnworker.delete_payment_info(payment_hash, False)
        else:
            self.lnworker.delete_invoice(swap.payment_hash, False)
            self.invoices_to_pay.pop(swap.payment_hash.hex(), None)
        self.invoices_awaiting_funding.discard(swap.payment_hash.hex())
        self._funding_gate_deadline.pop(swap.payment_hash.hex(), None)
        if swap.funding_txid is None or swap.is_redeemed:
            # issue #22 (audit F23): only a swap that leaves the record
            # store drops its chain watch. While our funding is live
            # on-chain the watcher MUST stay registered — the grace/refund
            # branch of _claim_swap is the only thing that recovers the
            # lockup after locktime; removing the callback here left the
            # UTXO unwatched until the next restart re-added it.
            self.lnwatcher.remove_callback(swap.lockup_address)
            self.swaps.pop(swap.payment_hash.hex())
        self.db.write()

    def _finish_normal_swap(self, swap: SwapData):
        self.logger.info(f'finishing normal swap {swap.payment_hash.hex()}')
        assert swap.preimage, f"Cannot settle without preimage: {swap.payment_hash.hex()}"
        hold_invoice = self.lnworker.get_hold_invoice(swap.payment_hash)
        hold_invoice.settle(swap.preimage)
        if not hold_invoice.funding_status == InvoiceState.SETTLED:
            self.logger.error(f'hold invoice settling failed: {swap.payment_hash.hex()}')
            return
        self.lnworker.delete_hold_invoice(swap.payment_hash, False)
        if swap.prepay_hash:
            self.lnworker.delete_hold_invoice(swap.prepay_hash, False)
        self.lnworker.delete_payment_info(swap.payment_hash, False)
        self.lnwatcher.remove_callback(swap.lockup_address)
        self.swaps.pop(swap.payment_hash.hex())
        self.db.write()

    def delete_finished_reverse_swap(self, swap: SwapData):
        """Used to delete remaining swap data after our claim transaction is confirmed on a reverse swap"""
        self.lnworker.delete_invoice(swap.payment_hash, False)
        self.lnwatcher.remove_callback(swap.lockup_address)
        self.invoices_to_pay.pop(swap.payment_hash.hex(), None)
        self.invoices_awaiting_funding.discard(swap.payment_hash.hex())
        self._funding_gate_deadline.pop(swap.payment_hash.hex(), None)
        if swap.funding_txid is None or swap.is_redeemed:
            self.swaps.pop(swap.payment_hash.hex(), None)
        self.db.write()

    def _payment_parked(self, swap: SwapData) -> bool:
        """True when OUR payment of the client's hold has committed
        HTLCs parked at the receiver — the #26 ordering gate signal.

        PAYER-SIDE TRUTH (live-earned 2026-08-24, jitlab, twice): the
        hold invoice lives at the CLIENT — the server can never query
        its received amount (implementation #1), and a bolt11-keyed
        listpays returns {'pays': [...]} whose unwrapped status is None
        (implementation #2 — deferred a parked swap for exactly this).
        The PROVEN query is listpays(payment_hash=...): entries with
        status 'pending' = HTLCs committed and parked at the receiver
        (xpay-209 'reached destination' semantics), 'complete' =
        settled. No entry = payment never started — defer (fail
        closed; the pay loop's attempt cap + CLTV bound the wait)."""
        try:
            out = self.lnworker._rpc.listpays(
                payment_hash=swap.payment_hash.hex())
            entries = out.get('pays', out) if isinstance(out, dict) else []
            if isinstance(entries, dict):
                entries = [entries]
            return any(p.get('status') in ('pending', 'complete')
                       for p in entries)
        except Exception:
            return False
    def _has_ln_commitment(self, swap: SwapData) -> bool:
        """True if the client committed to the LN leg of this reverse swap:
        it registered an invoice and the payment is not permanently failed.

        Settlement is deliberately NOT the criterion: a hold-invoice client
        can only settle after our claim reveals the preimage, so gating the
        claim on settlement would deadlock every honest swap."""
        key = swap.payment_hash.hex()
        if key in self.invoices_awaiting_funding:
            return True
        if key in self.invoices_to_pay:
            return True
        if self.lnworker.get_invoice(key) is not None:
            return True
        # covers completed payments (invoice deleted after success) and
        # in-flight attempts; 'failed' is permanently failed before flight
        statuses = self.lnworker.get_payment_statuses(key)
        return any(s in ('pending', 'inflight', 'complete') for s in statuses)

    def _funding_gate_m(self) -> int:
        # getattr-with-default keeps SimpleNamespace config fakes working
        # (same pattern as max_swap_amount in server_update_pairs)
        return int(getattr(self.config, 'funding_gate_timeout_blocks',
                           FUNDING_GATE_TIMEOUT_BLOCKS_DEFAULT))

    def _funding_gate_on_timeout(self) -> str:
        return str(getattr(self.config, 'funding_gate_on_timeout', 'fail')).strip().lower()

    async def funding_gate_watch_loop(self):
        """issue #24 option E (FUNDING-GATE-COMPAT-MEMO, operator-adopted):
        sub-block re-check of every invoice parked by the #12 funding
        gate. This is the memo's mempool-scripthash subscription realized
        on the bitcoind watch-wallet (get_addr_outputs is minconf=0, so a
        lockup sitting in mempool is already visible there — only the
        TRIGGER was block-bound before). Per pass: the bounded M-block
        timer runs (expiry-first, then fail-or-pay), and any still-parked
        swap gets a direct _claim_swap call so a mempool lockup discharges
        the gate and queues the payment without waiting for a block.
        Failure of a pass degrades to the block-boundary behavior of the
        ChainMonitor (memo rationale 5: slower but functional) — logged
        ERROR + tracker streak, never a death."""
        while True:
            await asyncio.sleep(FUNDING_GATE_POLL_SECONDS)
            tracker.beat('funding-gate-watcher',
                         detail=f'{len(self.invoices_awaiting_funding)} parked')
            if not self.invoices_awaiting_funding:
                continue
            try:
                await self._funding_gate_watch_pass()
            except Exception:
                self.logger.error(f'funding-gate watch pass failed (degraded to '
                                  f'block-boundary triggers):\n{traceback.format_exc()}')
                tracker.note_error('funding-gate-watcher', detail='pass failed')

    async def _funding_gate_watch_pass(self):
        current_height = await self.wallet.get_local_height()
        for key in list(self.invoices_awaiting_funding):
            swap = self.swaps.get(key)
            if swap is None:
                # already failed/finished elsewhere — drop the bookkeeping
                self.invoices_awaiting_funding.discard(key)
                self._funding_gate_deadline.pop(key, None)
                continue
            self._evaluate_funding_gate(swap, current_height)
            if key in self.invoices_awaiting_funding:
                # still parked: run the standard claim path so a mempool
                # lockup discharges the gate immediately (the payment
                # queues without waiting for a confirmation; the claim
                # broadcast itself stays >=1-conf gated, R1)
                await self._claim_swap(swap)

    def _evaluate_funding_gate(self, swap: SwapData, current_height: int) -> None:
        """The memo's bounded outcome for a parked invoice, in order:
        (1) a client invoice that already died fails as expired the
        moment we notice it — BEFORE any M timeout can fire (#25
        ordering: expiry wins); (2) at exactly M blocks past the
        addswapinvoice anchoring pass, fail (default) or pay per
        FUNDING_GATE_ON_TIMEOUT_BEHAVIOR."""
        key = swap.payment_hash.hex()
        if key not in self.invoices_awaiting_funding:
            return
        invoice = self.lnworker.get_invoice(key)
        if invoice is not None and invoice.has_expired():
            return self._fail_swap(
                swap, 'reverse swap invoice expired while awaiting lockup '
                      '(funding gate, #25 expiry-before-timeout ordering)')
        deadline = self._funding_gate_deadline.get(key)
        if deadline is None:
            self._funding_gate_deadline[key] = current_height + self._funding_gate_m()
            return
        if current_height < deadline:
            return
        if self._funding_gate_on_timeout() == 'pay':
            self.invoices_awaiting_funding.discard(key)
            self._funding_gate_deadline.pop(key, None)
            self.logger.warning(
                f'funding gate timeout for swap {key}: paying anyway '
                f'(FUNDING_GATE_ON_TIMEOUT_BEHAVIOR=pay — bounded jam '
                f'exposure of {self._funding_gate_m()} blocks per swap)')
            self.invoices_to_pay[key] = 0
        else:
            self._fail_swap(
                swap, f'funding gate timeout: no lockup observed '
                      f'{self._funding_gate_m()} blocks after addswapinvoice '
                      f'(issue #24 option E; a stock hold-invoice client that '
                      f'never saw our HTLC can retry with a new swap)')

    @log_exceptions
    async def _claim_swap(self, swap: SwapData) -> None:
        assert self.lnwatcher
        if not await self.lnwatcher.is_up_to_date():
            self.logger.warning('_claim_swap caled but core node not up to date, skipping')
            return
        current_height = await self.wallet.get_local_height()
        remaining_time = swap.locktime - current_height
        try:
            txos = await self.lnwatcher.get_addr_outputs(swap.lockup_address)
        except UnknownAddressError:
            # addresses are registered into the bitcoind wallet at swap
            # creation only; a restarted/recreated wallet loses the
            # import, and raising here crash-loops the chain callback
            # every block. Re-register and let the next block retry.
            # timestamp="now" means a lockup funded BEFORE the loss
            # needs a manual rescan to become claimable again.
            self.logger.warning(
                f'_claim_swap: {swap.lockup_address} lost its wallet import — re-registering')
            await self.lnwatcher.register_address(swap.lockup_address)
            return

        self.logger.debug(f'_claim_swap lockup addr: {swap.lockup_address} found {len(txos)} txout spending to it')
        for txin in txos:
            # Issue #7 (audit D-2, electrum parity): skip underfunded
            # outputs in BOTH directions — for normal swaps anyone can
            # pay dust decoys to the P2WSH lockup; a decoy that sorts
            # first would raise BelowDustLimit forever and block our
            # post-locktime refund.
            if txin.value_sats() < swap.onchain_amount:
                # amount too low, we must not reveal the preimage
                continue
            break
        else:
            # swap not funded.
            txin = None
            # if it is a normal swap, we might have double spent the funding tx
            # in that case we need to fail the HTLCs
            if swap.is_reverse:
                # issue #24 option E degraded mode: the block tick also
                # drives the bounded gate, so a dead funding-gate watcher
                # (or a bitcoind RPC outage during its passes) still
                # bounds the parking window — just at block cadence
                self._evaluate_funding_gate(swap, current_height)
            if remaining_time <= 0:
                return self._fail_swap(swap, 'expired')

        if txin:
            self.logger.debug(f'claim_swap found funding tx {txin.prevout.txid.hex()}')
            # the swap is funded
            # note: swap.funding_txid can change due to RBF, it will get updated here:
            swap.funding_txid = txin.prevout.txid.hex()
            swap._funding_prevout = txin.prevout
            self._add_or_reindex_swap(swap)  # to update _swaps_by_funding_outpoint
            # issue #22 (audit F10): funding_txid is a swap-state mutation
            # with an on-chain meaning — flush now, not whenever some later
            # path happens to write
            self.db.write()
            funding_height = await self.lnwatcher.get_tx_height(txin.prevout.txid.hex())
            spent_height = txin.spent_height
            should_bump_fee = False
            self.logger.debug(f"claim_swap: Swap funding output has been spent at height "
                              f"{spent_height} in tx {txin.spent_txid}")
            if spent_height is not None:
                swap.spending_txid = txin.spent_txid
                # issue #22 (audit F10): persist the observed spend before
                # any early-return branch below can skip a later write
                self.db.write()
                if spent_height > 0 and current_height - spent_height > REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                    self.logger.info(f'stop watching finished reverse swap {swap.lockup_address}')
                    swap.is_redeemed = True
                    # issue #22 (audit F10): flush is_redeemed before the
                    # delete path runs (which writes again) so a failure in
                    # between cannot lose the finished state
                    self.db.write()
                    return self.delete_finished_reverse_swap(swap)

            if not swap.is_reverse:
                if swap.preimage is None and spent_height is not None:
                    # extract the preimage, add it to lnwatcher
                    claim_tx = await self.lnwatcher.get_transaction(txin.spent_txid)
                    preimage = self.extract_preimage(swap, claim_tx)
                    if preimage is not None:
                        # the preimage is key material — log the hash it
                        # settles instead of the preimage itself (issue #13)
                        self.logger.debug(f"claim swap extracted preimage for "
                                          f"{swap.payment_hash.hex()} ({swap.lockup_address})")
                        swap.preimage = preimage.hex()
                        # issue #22 (audit F10): the extracted preimage is
                        # what settles the hold invoice — flush before the
                        # finish path runs (which writes again)
                        self.db.write()
                        return self._finish_normal_swap(swap)
                    else:
                        # this is our refund tx
                        if spent_height >= 2:
                            self.logger.info(f'failed normal swap refund tx confirmed: '
                                             f'{txin.spent_txid} @ {spent_height}')
                            swap.is_redeemed = True
                            # issue #22 (audit F10): flush before _fail_swap
                            self.db.write()
                            return self._fail_swap(swap, 'refund tx confirmed')
                        elif spent_height == 0:  # still unconfirmed, we check if bumping is neccessary
                            claim_tx_fee = claim_tx.get_fee()
                            recommended_fee = self.get_claim_fee()
                            if claim_tx_fee * 1.1 < recommended_fee:
                                should_bump_fee = True
                                self.logger.debug(f'claim tx fee too low {claim_tx_fee} < {recommended_fee}. we will bump the fee')

                if remaining_time > 0:
                    # too early for refund
                    self.logger.debug(f'claim_swap: remaining time {remaining_time} for {swap.lockup_address},'
                                      f'too early for refund')
                    return

                if swap.preimage:
                    # we have been paid. do not try to get refund.
                    self.logger.debug(f"claim_swap: we have been paid for {swap.lockup_address}, "
                                      f"not trying to get refund")
                    return

            else:
                if not getattr(swap, 'registered', False):
                    # issue #15 gate: claiming an unregistered lockup
                    # harvests the client's funds (no invoice exists, so
                    # no LN payment can ever balance it). Leave it
                    # refundable to the client's key at CLTV.
                    if funding_height.conf > 0:
                        self.logger.info(
                            f'claim gated: lockup funded but invoice never '
                            f'registered {swap.lockup_address} (abandoned swap) '
                            f'— staying refundable (issue #15)')
                    return
                if not self._payment_parked(swap):
                    # issue #26 ordering gate: claim only after OUR
                    # payment of the client's hold has parked. Claiming
                    # earlier leaves a client-loss corner (payment fails
                    # permanently post-claim ⇒ unfillable hold + lockup
                    # taken). Park-then-claim: the client can settle the
                    # moment the preimage is public; if our payment never
                    # parks, we never claim and the client refunds at CLTV.
                    self.logger.info(
                        f'claim deferred: payment not parked yet for '
                        f'{swap.lockup_address} (issue #26 park-then-claim)')
                    return

    @log_exceptions
    async def handle_request(self, request):
        assert self.sm.is_server
        # todo: remember event_id of already processed requests
        method = request.pop('method')
        event_id = request.pop('event_id')
        event_pubkey = request.pop('event_pubkey')
        self.logger.info(f'received swap request: id={event_id} {method} {request}')
        if method == 'addswapinvoice':
            handler = self.sm.server_add_swap_invoice
        elif method == 'createswap':
            handler = self.sm.server_create_swap
        elif method == 'createnormalswap':
            handler = self.sm.server_create_normal_swap
        else:
            handler = None
            r = {'error': f'unknown swap method: {method}'}
        if handler is not None and not self.sm.is_initialized.is_set():
            # issue #20 (audit F06): while the transport is dead/restarting
            # the offer is withdrawn; accepting swap work into a pipeline
            # that cannot serve it is the black-hole the audit flagged
            # (is_initialized used to stay set forever after consumer
            # death). A clean error reply the client can retry on.
            handler = None
            r = {'error': 'swap server unavailable (transport down), try again shortly'}
        if handler is not None:
            try:
                r = await handler(request) if asyncio.iscoroutinefunction(handler) else handler(request)
            except RequestFieldError as e:
                # malformed client input gets a REPLY, never silence —
                # the client would otherwise hang until its own timeout (#11)
                r = {'error': str(e)}
            except Exception:
                # internal errors too: the newaddr KeyError crash hung the
                # client for its full timeout — a server must always answer
                import traceback as _tb
                self.logger.error(f'internal error serving {method}: '
                                  f'{_tb.format_exc()}')
                r = {'error': f'internal error serving {method}'}
        r['reply_to'] = event_id
        self.logger.debug(f'sending response id={event_id}')
        await self.send_direct_message(event_pubkey, json.dumps(r))


    async def send_direct_message(self, pubkey: str, content: str) -> str:
        # PORT FIND #8: electrum_aionostr's direct_message= kwarg FORCES
        # kind=4, overriding kind= — replies went out as kind 4 while
        # current clients listen on 25582 and never matched them. Mirror
        # electrum's own server path: pre-encrypt, explicit kind, p-tag.
        our_private_key = aionostr.key.PrivateKey(self.private_key)
        recv_pubkey_hex = aionostr.util.from_nip19(pubkey)['object'].hex() if pubkey.startswith('npub') else pubkey
        encrypted = our_private_key.encrypt_message(content, recv_pubkey_hex)
        event_id = await aionostr._add_event(
            self.relay_manager,
            kind=self.NOSTR_DM,
            content=encrypted,
            private_key=self.nostr_private_key,
            tags=[['p', recv_pubkey_hex]])
        return event_id
