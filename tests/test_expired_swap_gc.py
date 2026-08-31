"""Issue #42: expired swap records never cleaned.

Live evidence (2026-08-31, cln-swap-signet, jsondb generation 1988): swap
21b4256e… (locktime 319851) sat 300+ blocks past locktime logging "claim
deferred: payment not parked yet" on EVERY watcher pass — an LN commitment
exists (payment attempted) but never parked, and no terminal transition
exists for that state. The record still carried its plaintext privkey +
preimage (old format) indefinitely, contrary to the #36 contract that
old-format secrets age out at expiry.

Contract under test: past locktime + SWEEP_GRACE_BLOCKS, a funded swap
whose LN leg is DEFINITIVELY never-parked (listpays answered: no pending,
no complete) is dead bookkeeping — the lockup stays client-refundable
forever (refund branch has no expiry), our claim is forfeit by policy
(#26 never-claim-unparked), so the record is dropped (secrets age out)
and the address unwatched. The payment layer is NEVER touched (parked
HTLCs ride to their own expiry — the #13 funds-safety guard), and an
RPC OUTAGE (listpays raising = unknown, not absent) must NOT expire a
live swap.

Run: python3 -m pytest tests/test_expired_swap_gc.py -v
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
import sys
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402


def _dead_swap() -> SwapData:
    # the 21b4256e production shape: old-format d2 (is_reverse=True on
    # the server), funded, never claimed, secrets in plaintext
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21403,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage="a1" * 32, prepay_hash=None, privkey="01" * 32,
        lockup_address="tb1qdead", receive_address="", funding_txid="c" * 64,
        spending_txid=None, is_redeemed=False, registered=True)
    swap._payment_hash = ("bb" * 32)
    return swap


def _manager(listpays_result=None, listpays_raises=False, height=5300):
    swap = _dead_swap()
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {swap._payment_hash: swap}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm.config = SimpleNamespace(sweep_grace_blocks=288)
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm._create_and_sign_claim_tx = MagicMock(
        return_value=MagicMock(txid=lambda: "f" * 64))
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=height)

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
        value_sats=lambda: 21403,
        block_height=height, spent_height=None, spent_txid=None)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.is_up_to_date = AsyncMock(return_value=True)
    sm.lnwatcher.broadcast_raw_transaction = AsyncMock(return_value="f" * 64)
    sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=[funded_txin])
    sm.lnwatcher.get_tx_height = AsyncMock(
        return_value=SimpleNamespace(conf=1))
    sm.lnworker = MagicMock()
    # LN commitment present (payment was attempted — the 21b4256e shape):
    # routes the watcher to the park gate, not the grace-hold branch
    sm.lnworker.get_invoice = MagicMock(return_value=object())
    sm.lnworker.get_payment_statuses = MagicMock(return_value=[])
    sm.lnworker.get_preimage = MagicMock(return_value=swap.preimage)
    sm.lnworker._rpc = MagicMock()
    if listpays_raises:
        sm.lnworker._rpc.listpays = MagicMock(side_effect=RuntimeError("rpc down"))
    else:
        sm.lnworker._rpc.listpays = MagicMock(
            return_value=listpays_result if listpays_result is not None
            else {"pays": []})
    return sm, swap


class TestNeverParkedExpiry:
    def test_definitively_never_parked_past_grace_expires_record(self):
        # locktime 5000 + grace 288 = 5288 < height 5300; listpays
        # ANSWERED with no pending/complete entries → terminal expiry
        sm, swap = _manager(height=5300)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()
        assert swap._payment_hash not in sm.swaps, \
            "dead never-parked record must be dropped (secrets age out)"
        sm.lnwatcher.remove_callback.assert_called_once_with(swap.lockup_address)
        sm.db.write.assert_called()
        assert any('expir' in str(c.args[0]).lower()
                   for c in sm.logger.error.call_args_list), \
            "terminal expiry must log at ERROR (policy line)"

    def test_rpc_outage_does_not_expire(self):
        # listpays RAISES = unknown, not absent — fail closed: record
        # stays, nothing is claimed (the #21 error-contract class)
        sm, swap = _manager(listpays_raises=True, height=5300)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()
        assert swap._payment_hash in sm.swaps

    def test_within_grace_defers_without_expiring(self):
        # height 5100 < 5288: same deferral as today, record intact
        sm, swap = _manager(height=5100)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_not_called()
        assert swap._payment_hash in sm.swaps

    def test_parked_payment_claims_instead_of_expiring(self):
        # definitive PARKED → the claim path proceeds (existing #26
        # contract; expiry must never fire on a live parked payment)
        sm, swap = _manager(
            listpays_result={"pays": [{"status": "pending"}]}, height=5300)
        asyncio.run(sm._claim_swap(swap))
        sm._create_and_sign_claim_tx.assert_called_once()
        assert swap._payment_hash in sm.swaps
