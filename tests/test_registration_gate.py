"""Issue #15: registration-blind claims — abandoned normal-swap lockups
must stay refundable.

Live evidence (2026-08-23, both provider classes, both networks): a
phase-1-only swap (hold NEVER registered) whose lockup got funded was
CLAIMED by the provider one block after confirmation — preimage branch,
hash-verified, no LN payment ever made or registrable. fund-before-
register is a funds-loss class; the claim must be gated on the client's
addswapinvoice registration (persisted flag — survives restarts).

Run: python3 -m pytest tests/test_registration_gate.py -v
"""
import asyncio
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
import sys
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402


def _d2_swap(registered: bool = False) -> SwapData:
    # d2 on the server = "reverse for server" = is_reverse=True
    # (server_create_normal_swap → create_reverse_swap)
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


def _manager_base(swap: SwapData) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.swaps = {swap._payment_hash: swap}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm._create_and_sign_claim_tx = MagicMock(
        return_value=MagicMock(txid=lambda: "f" * 64))
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=4900)

    class _Prevout:
        def __init__(self):
            self._txid = MagicMock(hex=lambda: "e" * 64)
            self.out_idx = 0
        @property
        def txid(self):
            return self._txid
        def __hash__(self):
            return hash(("e" * 64, 0))
        def __eq__(self, other):
            return isinstance(other, _Prevout)
    funded_txin = SimpleNamespace(
        prevout=_Prevout(),
        value_sats=lambda: 21181,
        block_height=4900, spent_height=None, spent_txid=None)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.is_up_to_date = AsyncMock(return_value=True)
    sm.lnwatcher.broadcast_raw_transaction = AsyncMock(return_value="f" * 64)
    sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=[funded_txin])
    sm.lnwatcher.get_tx_height = AsyncMock(
        return_value=SimpleNamespace(conf=1))          # lockup CONFIRMED
    sm.lnworker = MagicMock()
    return sm


def _manager(swap: SwapData) -> SwapManager:
    sm = _manager_base(swap)
    # default for the OLD tests: payment settled (they exercise the
    # registration gate, not the ordering gate)
    sm.lnworker.get_invoice = MagicMock(
        return_value=SimpleNamespace(lightning_invoice="lntbs-x"))
    sm.lnworker._rpc = MagicMock()
    sm.lnworker._rpc.listpays = MagicMock(return_value={"status": "complete"})
    return sm


class TestRegistrationGate:
    def test_unregistered_funded_swap_is_never_claimed(self):
        swap = _d2_swap(registered=False)
        sm = _manager(swap)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()

    def test_registered_funded_swap_claims(self):
        swap = _d2_swap()
        swap.registered = True                    # addswapinvoice ran
        sm = _manager(swap)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_called_once()

    def test_addswapinvoice_sets_the_persisted_flag(self):
        # source contract: server_add_swap_invoice must stamp
        # swap.registered = True (the persisted marker the gate reads)
        src = (_plugin / "submarine_swaps.py").read_text()
        assert re.search(r"swap\.registered\s*=\s*True", src), (
            "server_add_swap_invoice must set swap.registered = True")

    def test_gate_reads_the_registered_flag(self):
        # source contract: _claim_swap's reverse (d2) branch must gate
        # on swap.registered before the claim fall-through
        src = (_plugin / "submarine_swaps.py").read_text()
        assert re.search(r"if not .*registered", src), (
            "_claim_swap must gate the d2 claim on swap.registered")


class TestNostrLoopRobustness:
    def test_non_dict_dm_payloads_cannot_kill_the_listener(self):
        # live 2026-08-23 09:02: replayed junk DMs decrypting to a JSON
        # LIST crashed check_direct_messages (content['event_id'] on a
        # list) OUTSIDE the guarded block — nostr taskgroup died, plugin
        # DM-deaf until restart. The guard must precede the dict access.
        src = (_plugin / "submarine_swaps.py").read_text()
        assert re.search(
            r"isinstance\(content, dict\)[^\n]*\n\s*continue", src), (
            "check_direct_messages must skip non-dict payloads before "
            "any content['…'] access")


class TestParkBeforeClaim:
    """Issue #26: claim-vs-payment ordering — the d2 claim must not fire
    until OUR payment of the client's hold has parked (or settled).
    Current order has a client-loss corner: payment fails permanently
    AFTER the claim ⇒ client holds an unfillable hold while we took
    their lockup. Park-then-claim eliminates the corner on both sides
    (client refunds at CLTV; our HTLCs fail back)."""

    def _d2_registered_swap(self) -> SwapData:
        swap = _d2_swap()
        swap.registered = True
        return swap

    def _manager(self, swap, listpays_status=None, with_invoice=True):
        # payer-side truth (live-earned): the hold lives at the CLIENT;
        # the server's signal is listpays on the saved bolt11 —
        # 'pending' = HTLCs committed/parked at the receiver
        sm = _manager_base(swap)
        invoice = SimpleNamespace(lightning_invoice="lntbs-x") if with_invoice else None
        sm.lnworker.get_invoice = MagicMock(return_value=invoice)
        sm.lnworker._rpc = MagicMock()
        sm.lnworker._rpc.listpays = MagicMock(
            return_value={"status": listpays_status} if listpays_status else {})
        return sm

    def test_claim_gated_when_nothing_parked(self):
        swap = self._d2_registered_swap()
        # payment never started: no listpays entry at all
        sm = self._manager(swap, listpays_status=None)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()

    def test_claim_gated_when_payment_never_attempted_no_invoice(self):
        swap = self._d2_registered_swap()
        sm = self._manager(swap, with_invoice=False)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()

    def test_claim_fires_once_parked_pending(self):
        swap = self._d2_registered_swap()
        sm = self._manager(swap, listpays_status="pending")
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_called_once()

    def test_claim_fires_once_settled_complete(self):
        swap = self._d2_registered_swap()
        sm = self._manager(swap, listpays_status="complete")
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_called_once()

    def test_claim_deferred_on_listpays_error_fail_closed(self):
        swap = self._d2_registered_swap()
        sm = self._manager(swap, listpays_status="pending")
        sm.lnworker._rpc.listpays = MagicMock(side_effect=RuntimeError("rpc down"))
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()

    def test_gate_reads_the_parking_state(self):
        # source contract: the d2 branch must consult the hold's
        # received amount before the claim fall-through
        src = (_plugin / "submarine_swaps.py").read_text()
        assert re.search(r"parked", src), (
            "_claim_swap's d2 branch must gate on parking (received >= amount)")
