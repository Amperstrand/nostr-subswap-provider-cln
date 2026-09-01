"""Issue #52 regression suite (SECURITY-REVIEW 2026-08-31 hunter-3):
a mempool-stuck REVERSE claim had no bump path — should_bump_fee was only
set in the not-is_reverse branch, so a stuck claim returned early forever
(spent_height==0 + not should_bump_fee) and the only recovery was mempool
eviction.

Fix contract: the reverse branch mirrors the normal branch's underprice
check (claim_fee * 1.1 < recommended) and hands the rebuild a BIP-125
rule-4 fee floor — the replacement must pay minrelay for its own size on
top of the replaced fees, which the 1.1x heuristic alone under-shoots.
Claim txs signal RBF (TxInput default nsequence 0xfffffffe). A per-swap
bump budget (CLAIM_BUMP_MAX) caps oracle-flap escalation; past it,
recovery is mempool eviction.

Run: python3 -m pytest tests/test_issue_52_claim_bump.py -v
"""
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.constants import CLAIM_BUMP_MAX, RBF_MIN_INCREMENT_SATVB, CLAIM_FEE_SIZE  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402

STUCK_TXID = 'cc' * 32
NEW_TXID = 'ab' * 32


def _mk_swap(spending_txid=STUCK_TXID) -> SwapData:
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid='ff' * 32,
        spending_txid=spending_txid, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


def _fake_stuck_tx(fee_sat: int) -> MagicMock:
    t = MagicMock()
    t.get_fee.return_value = fee_sat
    return t


def _mk_sm(*, stuck_fee, recommended_fee) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._claim_bump_counts = {}
    sm._bump_capped_logged = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.config = SimpleNamespace(sweep_grace_blocks=288)
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1000)
    sm.wallet.get_chain_fee = MagicMock(return_value=recommended_fee)
    sm.lnworker = MagicMock()

    txin = MagicMock()
    txin.value_sats.return_value = 50_000
    txin.prevout.txid.hex.return_value = 'ff' * 32
    txin.spent_height = 0  # the claim IS the mempool spend
    txin.spent_txid = STUCK_TXID

    lnw = MagicMock()
    lnw.is_up_to_date = AsyncMock(return_value=True)
    lnw.get_addr_outputs = AsyncMock(return_value=[txin])
    lnw.get_tx_height = AsyncMock(return_value=SimpleNamespace(conf=1))
    lnw.get_transaction = AsyncMock(return_value=_fake_stuck_tx(stuck_fee))
    lnw.broadcast_raw_transaction = AsyncMock(return_value=NEW_TXID)
    sm.lnwatcher = lnw

    fake_tx = MagicMock()
    fake_tx.txid.return_value = NEW_TXID
    sm._create_and_sign_claim_tx = MagicMock(return_value=fake_tx)
    sm._has_ln_commitment = lambda s: True
    sm._payment_parked = lambda s: True
    return sm


class TestReverseClaimBump:
    async def test_underpriced_stuck_claim_gets_rbf_floor(self):
        """stuck at 100, recommended 200 → bump with the BIP-125 floor
        max(200, 100 + 1*136 + 1) = 237, not the bare 1.1x heuristic."""
        sm = _mk_sm(stuck_fee=100, recommended_fee=200)
        swap = _mk_swap()
        await sm._claim_swap(swap)
        assert sm._create_and_sign_claim_tx.call_count == 1
        kwargs = sm._create_and_sign_claim_tx.call_args.kwargs
        assert kwargs['fee_sat'] == max(200, 100 + RBF_MIN_INCREMENT_SATVB * CLAIM_FEE_SIZE + 1)
        sm.lnwatcher.broadcast_raw_transaction.assert_awaited_once()
        assert swap.spending_txid == NEW_TXID
        assert sm._claim_bump_counts[swap._payment_hash] == 1
        infos = [c.args[0] for c in sm.logger.info.call_args_list]
        assert any('RBF bumping stuck claim (#52)' in m for m in infos)

    async def test_adequately_priced_claim_is_left_alone(self):
        """stuck at 200, recommended 210 → 200*1.1 > 210: no rebuild, no
        rebroadcast — the early return for spent-not-bumping holds."""
        sm = _mk_sm(stuck_fee=200, recommended_fee=210)
        swap = _mk_swap()
        await sm._claim_swap(swap)
        sm._create_and_sign_claim_tx.assert_not_called()
        sm.lnwatcher.broadcast_raw_transaction.assert_not_awaited()

    async def test_bump_budget_cap_stops_escalation(self):
        sm = _mk_sm(stuck_fee=100, recommended_fee=200)
        swap = _mk_swap()
        sm._claim_bump_counts[swap._payment_hash] = CLAIM_BUMP_MAX
        await sm._claim_swap(swap)
        sm._create_and_sign_claim_tx.assert_not_called()
        errs = [c.args[0] for c in sm.logger.error.call_args_list]
        assert any('bump cap reached' in m and '(#52)' in m for m in errs)


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


class TestBothDirectionsSourceContract:
    def test_floor_formula_present_in_both_direction_branches(self):
        """#52 acceptance: the bump decision is pinned for BOTH
        directions — the BIP-125 floor must appear in the normal
        (refund) branch AND the reverse (claim) branch."""
        code = _code_only(_plugin / "submarine_swaps.py")
        assert code.count(
            "RBF_MIN_INCREMENT_SATVB * CLAIM_FEE_SIZE + 1") == 2, \
            "fee floor must be computed in both the normal and reverse branches"
        assert "should_bump_fee = True" in code
