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
from .utils import OldTaskGroup, now, BelowDustLimit, TxBroadcastError, ignore_exceptions, log_exceptions
from .bitcoin import DummyAddress
from .crypto import ripemd, sha256
from .lnutil import hex_to_bytes, REDEEM_AFTER_DOUBLE_SPENT_DELAY, bytes_to_hex
from .invoices import Invoice, InvoiceState
from .json_db import StoredObject, stored_in, JsonDB
from . import constants
from .constants import (MIN_LOCKTIME_DELTA, LOCKTIME_DELTA_REFUND, MAX_LOCKTIME_DELTA,
                       MIN_FINAL_CLTV_DELTA_FOR_CLIENT, CLAIM_FEE_SIZE, LOCKUP_FEE_SIZE,
                        MIN_FINAL_CLTV_DELTA_ACCEPTED, MIN_FINAL_CLTV_DELTA_FOR_INVOICE)
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
    # issue #15: a d2 lockup may only be claimed after the client's
    # addswapinvoice REGISTRATION — an abandoned swap (funded, never
    # registered) must stay refundable to the client's key at CLTV.
    # Persisted with the swap, so the gate survives restarts.
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
        self._swaps_by_funding_outpoint = {}  # type: Dict[TxOutpoint, SwapData]
        self._swaps_by_lockup_address = {}  # type: Dict[str, SwapData]
        for payment_hash_hex in list(self.swaps.keys()):
            swap = self.swaps[payment_hash_hex]
            payment_hash = bytes.fromhex(payment_hash_hex)
            swap._payment_hash = payment_hash_hex
            self._add_or_reindex_swap(swap)
            if not swap.is_reverse and not swap.is_redeemed:
                if self.lnworker.get_hold_invoice(payment_hash_hex) is not None:
                    self.lnworker.register_hold_invoice_callback(payment_hash=payment_hash,
                                                                 callback=self.hold_invoice_callback)
                else:  # invoice doesn't exist anymore
                    self.swaps.pop(payment_hash_hex)

        self.prepayments = {}  # type: Dict[bytes, bytes] # fee_rhash -> rhash
        for k, swap in self.swaps.items():
            if swap.prepay_hash is not None:
                self.prepayments[swap.prepay_hash] = bytes.fromhex(k)
        self.assert_constants()
        self.is_server = True  # this plugin is always a server
        self.use_nostr = True  # this plugin only uses nostr comm
        self.is_initialized = asyncio.Event()  # set once nostr is connected to relays

    @log_exceptions
    async def run_nostr_server(self):
        while True:
            try:
                with NostrTransport(config=self.config, sm=self) as transport:
                    await transport.is_connected.wait()
                    self.logger.info(f'nostr is connected')
                    last_advertised_max = None
                    while True:
                        # todo: publish everytime fees have changed
                        self.server_update_pairs()
                        await transport.publish_offer()
                        if not self.is_initialized.is_set():  # if publish offer didn't set initialized we retry faster
                            await asyncio.sleep(10)
                            continue
                        # converge fast while caps still move: the first
                        # pass after a restart races peer reconnection and
                        # advertises the 20k floor; recompute on a short
                        # cadence until the advertised cap stabilizes
                        if last_advertised_max != self._max_amount:
                            last_advertised_max = self._max_amount
                            await asyncio.sleep(30)
                        else:
                            await asyncio.sleep(600)
            except asyncio.TimeoutError:
                self.logger.warning(f"Nostr timeout, restarting Nostr module")
            await asyncio.sleep(15)

    async def main_loop(self):
        if self.is_initialized.is_set():
            raise Exception("swap manager main_loop called twice, already running")
        # readd all swaps to lnwatcher
        for k, swap in self.swaps.items():
            if swap.is_redeemed:
                continue
            self.add_lnwatcher_callback(swap)

        tasks = [
                    self.lnwatcher.trigger_callbacks(),  # trigger all callbacks once
                    self.pay_pending_ln_invoices(),
                    self.run_nostr_server()
                ]

        async with self.taskgroup as group:
            for task in tasks:
                await group.spawn(task)

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
        # attempt cap: an unpayable invoice (e.g. d2 bind whose hints the
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
        self.invoices_to_pay[key] = 1000000000000 # lock
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
            self._invoice_attempts.pop(key, None)
            self.lnworker.delete_invoice(key)
            self.invoices_to_pay.pop(key, None)

    async def pay_pending_ln_invoices(self):
        self.invoices_to_pay = {}
        self._invoice_attempts = {}
        while True:
            await asyncio.sleep(5)
            for key, not_before in list(self.invoices_to_pay.items()):
                if now() < not_before:
                    continue
                await self.taskgroup.spawn(self.pay_pending_ln_invoice(key))

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
        self.lnwatcher.remove_callback(swap.lockup_address)
        if swap.funding_txid is None or swap.is_redeemed:
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
        if swap.funding_txid is None or swap.is_redeemed:
            self.swaps.pop(swap.payment_hash.hex(), None)
        self.db.write()

    def _payment_parked(self, swap: SwapData) -> bool:
        """True when OUR payment of the client's hold has committed
        HTLCs parked at the receiver — the #26 ordering gate signal.

        PAYER-SIDE TRUTH (live-earned 2026-08-24, jitlab): the hold
        invoice lives at the CLIENT — the server can never query its
        received amount (the first implementation did exactly that and
        deferred a swap whose parking was already complete). The correct
        signal is our own listpays status: 'pending' = HTLCs committed
        and parked at the receiver (xpay-209 'reached destination'
        semantics); 'complete' = settled. No invoice / no entry =
        payment never started — defer (fail closed; the pay loop's
        attempt cap + CLTV bound the wait)."""
        try:
            invoice = self.lnworker.get_invoice(swap.payment_hash)
            bolt11 = getattr(invoice, 'lightning_invoice', None) if invoice else None
            if not bolt11:
                return False
            pays = self.lnworker._rpc.listpays(bolt11=bolt11)
            status = pays.get('status') if isinstance(pays, dict) else None
            return status in ('pending', 'complete')
        except Exception:
            return False

    @log_exceptions
    async def _claim_swap(self, swap: SwapData) -> None:
        assert self.lnwatcher
        if not await self.lnwatcher.is_up_to_date():
            self.logger.warning('_claim_swap caled but core node not up to date, skipping')
            return
        current_height = await self.wallet.get_local_height()
        remaining_time = swap.locktime - current_height
        txos = await self.lnwatcher.get_addr_outputs(swap.lockup_address)

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
            if remaining_time <= 0:
                return self._fail_swap(swap, 'expired')

        if txin:
            self.logger.debug(f'claim_swap found funding tx {txin.prevout.txid.hex()}')
            # the swap is funded
            # note: swap.funding_txid can change due to RBF, it will get updated here:
            swap.funding_txid = txin.prevout.txid.hex()
            swap._funding_prevout = txin.prevout
            self._add_or_reindex_swap(swap)  # to update _swaps_by_funding_outpoint
            funding_height = await self.lnwatcher.get_tx_height(txin.prevout.txid.hex())
            spent_height = txin.spent_height
            should_bump_fee = False
            self.logger.debug(f"claim_swap: Swap funding output has been spent at height "
                              f"{spent_height} in tx {txin.spent_txid}")
            if spent_height is not None:
                swap.spending_txid = txin.spent_txid
                if spent_height > 0 and current_height - spent_height > REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                    self.logger.info(f'stop watching finished reverse swap {swap.lockup_address}')
                    swap.is_redeemed = True
                    return self.delete_finished_reverse_swap(swap)

            if not swap.is_reverse:
                if swap.preimage is None and spent_height is not None:
                    # extract the preimage, add it to lnwatcher
                    claim_tx = await self.lnwatcher.get_transaction(txin.spent_txid)
                    preimage = self.extract_preimage(swap, claim_tx)
                    if preimage is not None:
                        self.logger.debug(f"claim swap extracted preimage: {preimage.hex()} for {swap.lockup_address}")
                        swap.preimage = preimage.hex()
                        return self._finish_normal_swap(swap)
                    else:
                        # this is our refund tx
                        if spent_height >= 2:
                            self.logger.info(f'failed normal swap refund tx confirmed: '
                                             f'{txin.spent_txid} @ {spent_height}')
                            swap.is_redeemed = True
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
                if swap.preimage is None:
                    swap.preimage = self.lnworker.get_preimage(swap.payment_hash)
                if swap.preimage is None:
                    if funding_height.conf <= 0:
                        return
                    key = swap.payment_hash.hex()
                    if remaining_time <= MIN_LOCKTIME_DELTA:
                        if key in self.invoices_to_pay:
                            # fixme: should consider cltv of ln payment
                            self.logger.debug(f'locktime too close {key} {remaining_time}')
                            self.invoices_to_pay.pop(key, None)
                        return
                    if key not in self.invoices_to_pay:
                        self.invoices_to_pay[key] = 0
                    return

            if spent_height is not None and not should_bump_fee:
                return
            try:
                tx = self._create_and_sign_claim_tx(txin=txin, swap=swap)
            except BelowDustLimit:
                self.logger.error('_claim_tx: utxo value below dust threshold')
                return
            swap.spending_txid = tx.txid()
            if funding_height.conf > 0: # or (swap.is_reverse and self.wallet.config.LIGHTNING_ALLOW_INSTANT_SWAPS):
                # Impl-note: HARD REQUIREMENT (swap protocol, not BOLT): only
                # Impl-note: broadcast the claim once the lockup has >= 1 confirmation.
                # Impl-note: The claim's witness REVEALS THE PREIMAGE, which settles
                # Impl-note: the lightning hold invoice irreversibly. Claiming an
                # Impl-note: unconfirmed lockup lets the payer double-spend the
                # Impl-note: funding while the preimage is already public: they keep
                # Impl-note: the onchain funds AND settle the invoice — we lose the
                # Impl-note: full swap amount.
                # Impl-note: The converse also holds: do NOT sit on a confirmed
                # Impl-note: lockup. Until the preimage is revealed, the payer's
                # Impl-note: HTLCs are parked (and their own BOLT #2 timeout
                # Impl-note: deadlines keep ticking), so delaying the claim risks
                # Impl-note: the payer's HTLCs failing and the swap dying even
                # Impl-note: though it was fully funded. Verified live
                # Impl-note: 2026-08-20: claim e3c670aa of lockup 4ecb1e4d
                # Impl-note: confirmed in the next block; invoice settled in
                # Impl-note: the same window.
                try:
                    self.logger.debug(f'spending claim tx {tx.txid()}: '
                                     f'\nTX_RAW: {Transaction.serialize(tx)}')
                    txid = await self.lnwatcher.broadcast_raw_transaction(Transaction.serialize(tx))
                    self.logger.info(f'broadcasted claim tx {txid}')
                except TxBroadcastError:
                    self.logger.error(f'error broadcasting claim tx {txin.spent_txid}. Report bug on github.')

    def get_claim_fee(self):
        return self.get_fee(size_vb=CLAIM_FEE_SIZE)

    def get_fee(self, *, size_vb: int) -> int:
        # note: 'size' is in vbytes
        return self.wallet.get_chain_fee(size_vbyte=size_vb)

    def add_lnwatcher_callback(self, swap: SwapData) -> None:
        callback = lambda: self._claim_swap(swap)
        self.lnwatcher.add_callback(swap.lockup_address, callback)

    @classmethod
    def extract_preimage(cls, swap: SwapData, claim_tx) -> Optional[bytes]:
        # Issue #2 (audit D-1, electrum parity): the client's claim tx can
        # contain legacy (non-witness) or unsigned inputs — indexing
        # witness_elements()[1] unconditionally raised IndexError, wedging
        # _claim_swap so the preimage was never registered and our parked
        # hold HTLCs failed at CLTV while the client kept the onchain claim.
        for claim_txin in claim_tx.inputs():
            witness = claim_txin.witness_elements()
            if not witness or len(witness) < 2:
                # tx may be unsigned, or a legacy input
                continue
            preimage = witness[1]
            if sha256(preimage) == swap.payment_hash:
                return preimage
        return None

    def hold_invoice_callback(self, payment_hash: bytes) -> None:
        # AUDIT A5: a provider must never park a payer's funds. Unknown
        # hash (post-restart orphan / replayed DM) or funding failure →
        # cancel the HTLCs NOW (electrum returns silently in both cases —
        # its payments hang until CLTV; our issue #10). create_funding_tx
        # was outside the try: an insufficient-onchain exception escaped
        # into the CLN htlc hook.
        key = payment_hash.hex()
        swap = self.swaps.get(key)
        if swap is None:
            invoice = self.lnworker.get_hold_invoice(payment_hash)
            if invoice:
                self.logger.warning(f'hold invoice {key[:10]} has no swap '
                                    'state — cancelling HTLCs')
                invoice.cancel_all_htlcs()
            return
        if swap.funding_txid is None:
            try:
                tx = self.create_funding_tx(swap=swap)
                self.broadcast_funding_tx(swap, tx)
            except Exception as e:
                self.logger.error(f'funding tx failed, failing swap {key[:10]}: {e}')
                self._fail_swap(swap, f'funding tx failed: {e}')

    def _require_amount(self, raw, field='invoiceAmount') -> int:
        """AUDIT A4: type/range validation with a clean error reply —
        _get_recv_amount returning None used to flow into script
        construction as None (traceback)."""
        if not isinstance(raw, int) or isinstance(raw, bool):
            raise RequestFieldError(f'{field} must be an integer, got {type(raw).__name__}')
        if raw <= 0:
            raise RequestFieldError(f'{field} must be positive, got {raw}')
        return raw

    def _require_fresh_payment_hash(self, payment_hash: bytes) -> None:
        """AUDIT A3: electrum's three duplicate-hash guards — a client
        replaying the same preimageHash clobbers swap state / hold
        invoices without them."""
        key = payment_hash.hex()
        if key in self.swaps:
            raise RequestFieldError('payment_hash already in use')
        if self.lnworker.get_preimage(payment_hash) is not None:
            raise RequestFieldError('payment_hash already in use')

    async def create_normal_swap(self, *, lightning_amount_sat: int, payment_hash: bytes, their_pubkey: bytes = None):
        """ server method """
        assert lightning_amount_sat
        locktime = await self.wallet.get_local_height() + LOCKTIME_DELTA_REFUND
        our_privkey = os.urandom(32)
        our_pubkey = ECPrivkey(our_privkey).get_public_key_bytes(compressed=True)
        onchain_amount_sat = self._get_recv_amount(lightning_amount_sat, is_reverse=True) # what the client is going to receive
        if onchain_amount_sat is None:
            # AUDIT A4: out of [min,max] bounds or below dust — was None
            # flowing into script construction (traceback)
            raise RequestFieldError(
                f'amount out of bounds or below dust '
                f'(min {self.get_min_amount()}, max {self.get_max_amount()})')
        redeem_script = construct_script(
            WITNESS_TEMPLATE_REVERSE_SWAP,
            {1:32, 5:ripemd(payment_hash), 7:their_pubkey, 10:locktime, 13:our_pubkey}
        )
        swap, invoice, prepay_invoice = await self.add_normal_swap(
            redeem_script=redeem_script,
            locktime=locktime,
            onchain_amount_sat=onchain_amount_sat,
            lightning_amount_sat=lightning_amount_sat,
            payment_hash=payment_hash,
            our_privkey=our_privkey,
            prepay=True,
        )
        # callback will be triggered when the swap invoice is paid to broadcast the funding tx
        self.lnworker.register_hold_invoice_callback(payment_hash=payment_hash, callback=self.hold_invoice_callback)
        return swap, invoice, prepay_invoice


    async def add_normal_swap(
            self, *,
            redeem_script: bytes,
            locktime: int,  # onchain
            onchain_amount_sat: int,
            lightning_amount_sat: int,
            payment_hash: bytes,
            our_privkey: bytes,
            prepay: bool,
            min_final_cltv_expiry_delta: Optional[int] = None,
    ) -> Tuple[SwapData, str, Optional[str]]:
        """creates a hold invoice"""
        if prepay:
            prepay_amount_sat = self.get_claim_fee() * 2
            invoice_amount_sat = lightning_amount_sat - prepay_amount_sat
        else:
            invoice_amount_sat = lightning_amount_sat

        invoice = self.lnworker.b11invoice_from_hash(
            payment_hash=payment_hash,
            amount_msat=invoice_amount_sat * 1000,
            message='Submarine swap',
            expiry=300,
            fallback_address=None,
            min_final_cltv_expiry_delta=min_final_cltv_expiry_delta,
        )

        if prepay:
            prepay_hash = self.lnworker.create_payment_info(amount_msat=prepay_amount_sat*1000)
            prepay_invoice = self.lnworker.b11invoice_from_hash(
                payment_hash=prepay_hash,
                amount_msat=prepay_amount_sat * 1000,
                message='Submarine swap mining fees',
                expiry=300,
                fallback_address=None,
                min_final_cltv_expiry_delta=min_final_cltv_expiry_delta,
            )

            self.lnworker.bundle_payments(swap_invoice=invoice, prepay_invoice=prepay_invoice)
            self.prepayments[prepay_hash] = payment_hash
        else:
            prepay_invoice = None
            prepay_hash = None

        lockup_address = script_to_p2wsh(redeem_script, net=self.config.network)
        receive_address = self.wallet.get_receiving_address()
        swap = SwapData(
            redeem_script=redeem_script.hex(),
            locktime = locktime,
            privkey = our_privkey.hex(),
            preimage = None,
            prepay_hash = prepay_hash.hex(),
            lockup_address = lockup_address,
            onchain_amount = onchain_amount_sat,
            receive_address = receive_address,
            lightning_amount = lightning_amount_sat,
            is_reverse = False,
            is_redeemed = False,
            funding_txid = None,
            spending_txid = None,
        )
        swap._payment_hash = bytes_to_hex(payment_hash)
        self._add_or_reindex_swap(swap)
        await self.lnwatcher.register_address(lockup_address)  # adds the address to the bcore wallet
        self.add_lnwatcher_callback(swap)
        return swap, invoice.bolt11, prepay_invoice.bolt11

    async def create_reverse_swap(self, *, lightning_amount_sat: int, their_pubkey: bytes) -> SwapData:
        """ server method. """
        assert lightning_amount_sat is not None
        locktime = await self.wallet.get_local_height() + LOCKTIME_DELTA_REFUND
        privkey = os.urandom(32)
        our_pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
        onchain_amount_sat = self._get_send_amount(lightning_amount_sat, is_reverse=False)
        if onchain_amount_sat is None:
            raise RequestFieldError(
                f'amount out of bounds (min {self.get_min_amount()}, '
                f'max {self.get_max_amount()})')
        preimage = os.urandom(32)
        payment_hash = sha256(preimage)
        redeem_script = construct_script(
            WITNESS_TEMPLATE_REVERSE_SWAP,
            {1:32, 5:ripemd(payment_hash), 7:our_pubkey, 10:locktime, 13:their_pubkey}
        )
        swap = await self.add_reverse_swap(
            redeem_script=redeem_script,
            locktime=locktime,
            privkey=privkey,
            preimage=preimage,
            payment_hash=payment_hash,
            prepay_hash=None,  # server doesn't prepay
            onchain_amount_sat=onchain_amount_sat,
            lightning_amount_sat=lightning_amount_sat)
        return swap

    async def add_reverse_swap(
        self,
        *,
        redeem_script: bytes,
        locktime: int,  # onchain
        privkey: bytes,
        lightning_amount_sat: int,
        onchain_amount_sat: int,
        preimage: bytes,
        payment_hash: bytes,
        prepay_hash: Optional[bytes] = None,
    ) -> SwapData:
        lockup_address = script_to_p2wsh(redeem_script, net=self.config.network)
        receive_address = self.wallet.get_receiving_address()
        await self.lnwatcher.register_address(lockup_address)
        swap = SwapData(
            redeem_script = bytes_to_hex(redeem_script),
            locktime = locktime,
            privkey = bytes_to_hex(privkey),
            preimage = bytes_to_hex(preimage),
            prepay_hash = bytes_to_hex(prepay_hash),
            lockup_address = lockup_address,
            onchain_amount = onchain_amount_sat,
            receive_address = receive_address,
            lightning_amount = lightning_amount_sat,
            is_reverse = True,
            is_redeemed = False,
            funding_txid = None,
            spending_txid = None,
        )
        if prepay_hash:
            self.prepayments[prepay_hash] = payment_hash
        swap._payment_hash = bytes_to_hex(payment_hash)
        self._add_or_reindex_swap(swap)

        self.add_lnwatcher_callback(swap)
        return swap

    def server_add_swap_invoice(self, request: dict) -> dict:
        # AUDIT A2: electrum validates far more here — port its checks and
        # reply with clean errors instead of raw asserts. The hash check
        # specifically: an invoice whose rhash != swap hash must NEVER be
        # accepted (observed live 2026-08-19: external provider c70d7bc9
        # accepted a mismatched invoice and claimed the client's lockup —
        # playground issue #16 evidence).
        try:
            invoice = Invoice.from_bech32(request['invoice'])
        except Exception as e:
            raise RequestFieldError(f'invoice is not valid bolt11: {e!r}')
        # Issue #4: BOLT #11 reader MUSTs at the boundary — malformed
        # invoices (bad p/s length, d/h xor, missing secret, unknown even
        # feature bits) reject HERE, before any state mutation.
        check_invoice_before_payment(request['invoice'])
        key = invoice.rhash
        payment_hash = bytes.fromhex(key)
        their_pubkey = self._parse_client_key(
            'refundPublicKey', request.get('refundPublicKey', ''), 33)
        swap = self.swaps.get(key)
        if swap is None or not swap.is_reverse:
            raise RequestFieldError('unknown swap for this invoice')
        if swap.lightning_amount != int(invoice.get_amount_sat() or 0):
            raise RequestFieldError(
                f'invoice amount != swap amount '
                f'({invoice.get_amount_sat()} != {swap.lightning_amount})')
        if sha256(hex_to_bytes(swap.preimage)) != payment_hash:
            raise RequestFieldError('invoice hash does not match the swap')
        if swap.spending_txid is not None:
            raise RequestFieldError('swap already in flight')
        # re-derive the redeem script: their_pubkey must reproduce
        # phase-1's script or the refund path silently mis-binds.
        # Role order for d2 (create_reverse_swap): slot 7 = CLAIM key =
        # OURS (server claims with preimage), slot 13 = REFUND key =
        # THEIRS. The d1 order (create_normal_swap) is the inverse —
        # copying it here rejected every legit bind (earned live; the
        # direction-inversion trap the AGENTS terminology table warns of).
        # SwapData.privkey is HEX in this port (see sign_tx) — ECPrivkey
        # asserts raw bytes.
        our_pubkey = ECPrivkey(hex_to_bytes(swap.privkey)).get_public_key_bytes(compressed=True)
        redeem_script = construct_script(
            WITNESS_TEMPLATE_REVERSE_SWAP,
            {1: 32, 5: ripemd(payment_hash), 7: our_pubkey,
             10: swap.locktime, 13: their_pubkey}
        )
        # swap.redeem_script is HEX-string storage (bytes_to_hex in both
        # add_*_swap paths) — comparing it raw against bytes is ALWAYS
        # unequal and rejected every legit bind (earned live, same
        # hex-vs-bytes class as the privkey trap)
        if bytes.fromhex(swap.redeem_script) != redeem_script:
            raise RequestFieldError('refundPublicKey does not match phase-1')
        if key in self.invoices_to_pay:
            raise RequestFieldError('invoice already bound')
        swap.registered = True
        self.lnworker.save_invoice(invoice)
        self.invoices_to_pay[key] = 0
        return {}

    def create_funding_tx(
        self,
        *,
        swap: SwapData,
    ) -> PartialTransaction:
        # create funding tx
        # note: rbf must not decrease payment
        funding_output = PartialTxOutput.from_address_and_value(swap.lockup_address, swap.onchain_amount)
        tx = self.wallet.create_transaction(
            outputs_without_change=[funding_output],
            rbf=True,
        )
        # fundpsbt failure (starved wallet / no live utxos) returns None —
        # raise a descriptive error so hold_invoice_callback's handler
        # fails the swap cleanly instead of the ChainMonitor crashing on
        # 'NoneType has no attribute inputs' (earned live)
        if tx is None:
            raise Exception('create_funding_tx: wallet could not fund the '
                            'lockup (fundpsbt failed — check onchain '
                            'balance and reservations)')
        return tx

    # upstream bug (port find #2): @log_exceptions asserts its target is
    # a coroutine — on this sync method it crashed the entire module at
    # import, so upstream's own tests could never import it
    def broadcast_funding_tx(self, swap: SwapData, tx: PartialTransaction) -> None:
        swap.funding_txid = tx.txid()
        self.wallet.broadcast_transaction(tx)

    def _add_or_reindex_swap(self, swap: SwapData) -> None:
        if swap.payment_hash.hex() not in self.swaps:
            self.swaps[swap.payment_hash.hex()] = swap
        if swap._funding_prevout:
            self._swaps_by_funding_outpoint[swap._funding_prevout] = swap
        self._swaps_by_lockup_address[swap.lockup_address] = swap

    def server_update_pairs(self) -> None:
        """ for server """
        # AUDIT/#14 true root cause: float fee math. float(2000)/10000 ->
        # Decimal(float) = 0.2000000000000000111… overcharges by 1 sat vs
        # the client's Decimal(str(offer 0.2)) -> strict quote check fails
        # (19671 < 19672, earned live). Pure Decimal, electrum-parity
        # (submarine_swaps.py:1374). Offer builder's float() still emits 0.2.
        self.percentage = Decimal(self.config.swapserver_fee_millionths) / Decimal(10000)
        self._min_amount = 20000
        # R3: advertised cap must be config-driven (MAX_SWAP_AMOUNT env,
        # default 10M). A hardcoded 10M made the offer LIE on signet where
        # real capacity is a few hundred k — clients would negotiate swaps
        # the node can't fund. Plugin config clamps to available capacity
        # at update time (min(env cap, spendable onchain, LN send+recv)).
        self._max_amount = min(
            int(getattr(self.config, "max_swap_amount", 10_000_000)),
            max(20000, int(self.wallet.balance_sat())),
            max(20000, int(self.lnworker.num_sats_can_receive())
                + int(self.lnworker.num_sats_can_send())),
        )
        # PORT FIND #9: one mining_fee everywhere, like electrum's server.
        # The client derives its expected onchainAmount from the OFFER's
        # mining_fee (pre-batcher formula), then also subtracts it again
        # as its own claim cost in get_recv_amount. If the server
        # subtracts a DIFFERENT fee (we used a 153-vB lockup fee = 155
        # while the offer said 138), the client's strict equality check
        # fails: 'onchain_amount is not what we estimated' / '< expected'.
        # AUDIT A1 (#14): electrum adopts a new mining_fee only when it
        # moved >10% (submarine_swaps.py:1382) — without that hysteresis
        # our live-CLN-feerate re-cache drifted quotes off the published
        # offer within minutes. Mirror the hysteresis exactly.
        new_fee = self.get_fee(size_vb=CLAIM_FEE_SIZE)
        if self.normal_fee is None or \
                abs(self.normal_fee - new_fee) / self.normal_fee > 0.1:
            self.normal_fee = new_fee
        self.lockup_fee = self.normal_fee
        self.claim_fee = self.normal_fee

    def get_max_amount(self):
        return self._max_amount

    def get_min_amount(self):
        return self._min_amount

    def check_invoice_amount(self, x):
        return self.get_min_amount() <= x <= self.get_max_amount()

    def _get_recv_amount(self, send_amount: Optional[int], *, is_reverse: bool) -> Optional[int]:
        """For a given swap direction and amount we send, returns how much we will receive.

        Note: in the reverse direction, the mining fee for the on-chain claim tx is NOT accounted for.
        In the reverse direction, the result matches what the swap server returns as response["onchainAmount"].
        """
        if send_amount is None:
            return
        x = Decimal(send_amount)
        percentage = Decimal(self.percentage)
        if is_reverse:
            if not self.check_invoice_amount(x):
                return
            # see/ref:
            # https://github.com/BoltzExchange/boltz-backend/blob/e7e2d30f42a5bea3665b164feb85f84c64d86658/lib/service/Service.ts#L948
            percentage_fee = math.ceil(percentage * x / 100)
            base_fee = self.lockup_fee
            x -= percentage_fee + base_fee
            x = math.floor(x)
            if x < dust_threshold():
                return
        else:
            x -= self.normal_fee
            percentage_fee = math.ceil(x * percentage / (100 + percentage))
            x -= percentage_fee
            if not self.check_invoice_amount(x):
                return
        x = int(x)
        return x

    def _get_send_amount(self, recv_amount: Optional[int], *, is_reverse: bool) -> Optional[int]:
        """For a given swap direction and amount we want to receive, returns how much we will need to send.

        Note: in the reverse direction, the mining fee for the on-chain claim tx is NOT accounted for.
        In the forward direction, the result matches what the swap server returns as response["expectedAmount"].
        """
        if not recv_amount:
            return
        x = Decimal(recv_amount)
        percentage = Decimal(self.percentage)
        if is_reverse:
            # see/ref:
            # https://github.com/BoltzExchange/boltz-backend/blob/e7e2d30f42a5bea3665b164feb85f84c64d86658/lib/service/Service.ts#L928
            # https://github.com/BoltzExchange/boltz-backend/blob/e7e2d30f42a5bea3665b164feb85f84c64d86658/lib/service/Service.ts#L958
            base_fee = self.lockup_fee
            x += base_fee
            x = math.ceil(x / ((100 - percentage) / 100))
            if not self.check_invoice_amount(x):
                return
        else:
            if not self.check_invoice_amount(x):
                return
            # see/ref:
            # https://github.com/BoltzExchange/boltz-backend/blob/e7e2d30f42a5bea3665b164feb85f84c64d86658/lib/service/Service.ts#L708
            # https://github.com/BoltzExchange/boltz-backend/blob/e7e2d30f42a5bea3665b164feb85f84c64d86658/lib/rates/FeeProvider.ts#L90
            percentage_fee = math.ceil(percentage * x / 100)
            x += percentage_fee + self.normal_fee
        x = int(x)
        return x

    @classmethod
    def sign_tx(cls, tx: PartialTransaction, swap: SwapData) -> None:
        preimage = hex_to_bytes(swap.preimage) if swap.is_reverse else 0
        witness_script = hex_to_bytes(swap.redeem_script)
        txin = tx.inputs()[0]
        assert len(tx.inputs()) == 1, f"expected 1 input for swap claim tx. found {len(tx.inputs())}"
        assert txin.prevout.txid.hex() == swap.funding_txid
        txin.script_sig = b''
        txin.witness_script = witness_script
        sig = tx.sign_txin(0, hex_to_bytes(swap.privkey))
        witness = [sig, preimage, witness_script]
        txin.witness = construct_witness(witness)

    def _create_and_sign_claim_tx(
        self,
        *,
        txin: PartialTxInput,
        swap: SwapData,
    ) -> PartialTransaction:
        # FIXME the mining fee should depend on swap.is_reverse.
        #       the txs are not the same size...
        amount_sat = txin.value_sats() - self.get_fee(size_vb=CLAIM_FEE_SIZE)
        if amount_sat < dust_threshold():
            raise BelowDustLimit()
        if swap.is_reverse:  # successful reverse swap
            locktime = 0
            # preimage will be set in sign_tx
        else:  # timing out forward swap
            locktime = swap.locktime
        tx = create_claim_tx(
            txin=txin,
            witness_script=swap.redeem_script,
            address=swap.receive_address,
            amount_sat=amount_sat,
            locktime=locktime,
        )
        self.sign_tx(tx, swap)
        tx.finalize_psbt()
        return tx

    @staticmethod
    def _parse_client_key(field: str, raw, expected_len: int):
        """Hex pubkey/hash parse with a clean error payload instead of a
        traceback (a malformed client field must yield a reply the client
        can act on, never a dropped request — issue #11)."""
        try:
            val = bytes.fromhex(raw)
        except (ValueError, TypeError):
            raise RequestFieldError(
                f'{field} must be hex, got len={len(raw) if isinstance(raw, str) else type(raw).__name__}')
        if len(val) != expected_len:
            raise RequestFieldError(
                f'{field} must be {expected_len * 2} hex chars, got {len(val) * 2}')
        return val

    async def server_create_normal_swap(self, request):
        # normal for client, reverse for server
        #request = await r.json()
        lightning_amount_sat = self._require_amount(request['invoiceAmount'])
        their_pubkey = self._parse_client_key('refundPublicKey', request['refundPublicKey'], 33)
        assert len(their_pubkey) == 33
        if self.lnworker.num_sats_can_send() < lightning_amount_sat:
            self.logger.warning(f'not enough outgoing capacity to satisfy swap: {self.lnworker.num_sats_can_send()} sat,'
                                f' rejecting swap for {lightning_amount_sat} sat')
            return {'error': 'not enough outgoing capacity'}
        swap = await self.create_reverse_swap(
            lightning_amount_sat=lightning_amount_sat,
            their_pubkey=their_pubkey,
        )
        response = {
            "id": swap.payment_hash.hex(),
            'preimageHash': swap.payment_hash.hex(),
            "acceptZeroConf": False,
            "expectedAmount": swap.onchain_amount,
            "timeoutBlockHeight": swap.locktime,
            "address": swap.lockup_address,
            "redeemScript": swap.redeem_script,
        }
        return response

    async def server_create_swap(self, request):
        # reverse for client, forward for server
        # requesting a normal swap (old protocol) will raise an exception
        #request = await r.json()
        req_type = request['type']
        assert request['pairId'] == 'BTC/BTC'
        if req_type == 'reversesubmarine':
            lightning_amount_sat=self._require_amount(request['invoiceAmount'])
            payment_hash=self._parse_client_key('preimageHash', request['preimageHash'], 32)
            their_pubkey=self._parse_client_key('claimPublicKey', request['claimPublicKey'], 33)
            self._require_fresh_payment_hash(payment_hash)
            assert len(payment_hash) == 32
            assert len(their_pubkey) == 33
            if self.lnworker.num_sats_can_receive() < lightning_amount_sat:
                self.logger.warning(f'not enough incoming capacity to receive swap: '
                                    f'{self.lnworker.num_sats_can_receive()}, '
                                    f'rejecting swap for {lightning_amount_sat}sat')
                return {'error': 'not enough incoming capacity, please open channel'}
            if self.wallet.balance_sat() < lightning_amount_sat:
                self.logger.warning(f'not enough onchain balance to satisfy: {self.wallet.balance_sat()} sat'
                                    f', rejecting swap for {lightning_amount_sat} sat')
                return {'error': 'not enough onchain balance'}
            swap, invoice, prepay_invoice = await self.create_normal_swap(
                lightning_amount_sat=lightning_amount_sat,
                payment_hash=payment_hash,
                their_pubkey=their_pubkey
            )
            response = {
                'id': payment_hash.hex(),
                'invoice': invoice,
                'minerFeeInvoice': prepay_invoice,
                'lockupAddress': swap.lockup_address,
                'redeemScript': swap.redeem_script,
                'timeoutBlockHeight': swap.locktime,
                "onchainAmount": swap.onchain_amount,
            }
        elif req_type == 'submarine':
            response = {
                'error': 'Deprecated API. Please upgrade your version of Electrum'
            }
        else:
            response = {
                'error': f'unsupported request type: {req_type}'
            }
        return response


class NostrTransport:  # (Logger):
    # uses nostr:
    #  - to advertise servers
    #  - for client-server RPCs (using DMs)
    #     (todo: we should use onion messages for that)

    # electrum ≥4.6 uses ephemeral kind 25582 for swap DMs (the plugin's
    # 2025-era kind 4 never sees current clients' requests — port find #7;
    # matches boltz-bridge's nostr-transport kind)
    NOSTR_DM = 25582
    STATUS_NIP38 = 30315
    FEE_UPDATE_INVERVAL_SEC = 60*10
    NOSTR_EVENT_TIMEOUT = 60*60*24
    NOSTR_EVENT_VERSION = 2

    def __init__(self, *, config, sm):
        self.logger = config.logger
        self.config = config
        self.relays = config.nostr_relays
        self.sm = sm
        self.offers = {}
        keypair = config.nostr_keypair
        self.private_key = keypair.privkey
        self.nostr_private_key = to_nip19('nsec', keypair.privkey.hex())
        self.nostr_pubkey = keypair.pubkey.hex()[2:]
        self.dm_replies = defaultdict(asyncio.Future)  # type: Dict[bytes, asyncio.Future]
        self.relay_manager = aionostr.Manager(self.relays, private_key=self.nostr_private_key)
        self.is_connected = asyncio.Event()
        self.taskgroup = OldTaskGroup()

    def __enter__(self):
        asyncio.create_task(self.main_loop())  # , self.network.asyncio_loop)
        return self

    def __exit__(self, ex_type, ex, tb):
        asyncio.create_task(self.stop())  # , self.network.asyncio_loop)

    @log_exceptions
    async def main_loop(self):
        assert self.sm.is_server, "This is a CLN plugin and should always run as server"
        self.logger.info(f'starting nostr transport with pubkey: {self.nostr_pubkey}')
        self.logger.info(f'nostr relays: {self.relays}')
        await self.relay_manager.connect()
        # electrum_aionostr's connect() is fire-and-forget: it returns
        # before websocket handshakes finish, filters self.relays to the
        # already-connected (often none), and a subscribe over zero
        # relays cleanly ENDS the get_events generator (empty-queue EOSE
        # sentinel) — the DM listener died instantly and silently with
        # the 2025 fork's blocking connect(). Wait for readiness.
        for _ in range(120):
            if any(r.connected for r in self.relay_manager.relays):
                break
            await asyncio.sleep(0.5)
        else:
            self.logger.error("nostr relays never became ready")
        self.is_connected.set()
        try:
            async with self.taskgroup as group:
                await group.spawn(self.check_direct_messages())
        except Exception:
            self.logger.error(f"Nostr taskgroup died. {traceback.format_exc()}")
        finally:
            self.logger.warning("Nostr taskgroup stopped.")

    async def stop(self):
        self.logger.warning("shutting down nostr transport")
        self.sm.is_initialized.clear()
        # trying to gracefully shut down what's left of the NostrTransport
        for coro in [self.relay_manager.close, self.taskgroup.cancel_remaining]:
            try:
                await coro()
            except Exception:
                pass

    async def publish_offer(self):
        assert self.sm.is_server
        # wire format: plugin.offer (electrum 4.8.1 parity; the old
        # 2025 format — no pow_nonce, pre-versioning d-tag — is rejected
        # by every current client; see PORT-NOTES.md)
        from .offer import build_offer_content, build_offer_tags
        content = build_offer_content(
            percentage_fee=self.sm.percentage,
            mining_fee_sat=self.sm.normal_fee,
            min_amount_sat=self.sm._min_amount,
            max_forward_sat=self.sm._max_amount,
            max_reverse_sat=self.sm._max_amount,
            relays_csv=self.sm.config.nostr_relays_csv,
            pow_nonce=self.config.ann_pow_nonce,
            # percent units, matching percentage_fee semantics; 0 hides
            # the key entirely (non-JIT providers keep identical offers)
            jit_channel_pct=jit_liquidity_factor(self.sm.lnworker._rpc) * 100,
            # self-ID baked at image build (git describe); stock electrum
            # and third parties do not send this key
            server_version=os.environ.get('SWAP_PROVIDER_VERSION', 'cln-subswap/dev'))
        tags = build_offer_tags(net_name=self.config.net_name)
        event_id = await aionostr._add_event(
            self.relay_manager,
            kind=self.STATUS_NIP38,
            content=content,
            tags=tags,
            private_key=self.nostr_private_key)
        self.logger.debug(f'published offer: {content} | event id: {event_id}')
        self.sm.is_initialized.set()

    @log_exceptions
    async def check_direct_messages(self):
        privkey = aionostr.key.PrivateKey(self.private_key)
        query = {"kinds": [self.NOSTR_DM], "limit":0, "#p": [self.nostr_pubkey]}
        # PORT FIND #13: the relay STORES swap DMs (ephemeral kind or not),
        # so every restart REPLAYS them. A replayed addswapinvoice hits
        # 'assert spending_txid is None' on an already-spent swap and the
        # AssertionError killed the entire nostr taskgroup — one old DM
        # murdered the transport. Per-event isolation: log, skip, survive.
        seen_event_ids = set()
        async for event in self.relay_manager.get_events(query, single_event=False, only_stored=False):
            try:
                content = privkey.decrypt_message(event.content, event.pubkey)
                content = json.loads(content)
            except Exception:
                continue
            # PORT FIND #13 escapee (live 2026-08-23 09:02): a payload that
            # decrypts to a NON-DICT (a JSON list — malformed/malicious
            # replay DMs) reached content['event_id'] below and raised
            # TypeError('list indices must be integers or slices, not str')
            # OUTSIDE any guard — killing the whole nostr taskgroup and
            # leaving the plugin DM-deaf until restart. Skip junk shapes.
            if not isinstance(content, dict):
                continue
            if event.id in seen_event_ids:
                continue
            seen_event_ids.add(event.id)
            content['event_id'] = event.id
            content['event_pubkey'] = event.pubkey
            if 'reply_to' in content:
                self.dm_replies[content['reply_to']].set_result(content)
            elif self.sm.is_server and 'method' in content:
                # handle_request POPS event_id/event_pubkey from the dict —
                # capture first or the failure log below KeyErrors (the
                # exact second-order crash the first #13 fix produced)
                req_event_id = content['event_id']
                try:
                    await self.handle_request(content)
                except Exception:
                    self.logger.warning(
                        f"swap request {req_event_id[:10]} failed (likely "
                        f"replay of an already-executed request) — skipped:\n"
                        f"{traceback.format_exc()}")
            else:
                print('unknown message', content)

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
