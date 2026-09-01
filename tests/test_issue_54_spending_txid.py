"""Issue #54 regression suite (SECURITY-REVIEW 2026-08-31 hunter-1):
spending_txid — the addswapinvoice 'already in flight' marker — was
persisted BEFORE the broadcast result was known. A witness-invalid claim
loop keeps retrying forever (spent_height stays None) while the client
permanently sees 'swap already in flight', masking the retry state.

Fix contract: the pre-broadcast persist is the forensic intent marker
(claim_intent_txid, the #22 audit F10 crash-safety contract); spending_txid
is stamped ONLY after broadcast_raw_transaction returns. The chain-observed
spend (_claim_swap's reconciliation path) remains the authoritative
overwrite.

Run: python3 -m pytest tests/test_issue_54_spending_txid.py -v
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

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinCoreRPCError  # noqa: E402

CLAIM_TXID = 'ab' * 32


def _mk_swap(**over) -> SwapData:
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    for k, v in over.items():
        setattr(swap, k, v)
    return swap


def _mk_sm(broadcast=None) -> SwapManager:
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
    sm._orphan_first_seen = {}
    sm._orphan_reported = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.config = SimpleNamespace(sweep_grace_blocks=288)
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1000)
    sm.lnworker = MagicMock()

    txin = MagicMock()
    txin.value_sats.return_value = 50_000
    txin.prevout.txid.hex.return_value = 'ff' * 32
    txin.spent_height = None
    txin.spent_txid = 'cc' * 32

    lnw = MagicMock()
    lnw.is_up_to_date = AsyncMock(return_value=True)
    lnw.get_addr_outputs = AsyncMock(return_value=[txin])
    lnw.get_tx_height = AsyncMock(return_value=SimpleNamespace(conf=1))
    if broadcast is None:
        lnw.broadcast_raw_transaction = AsyncMock(return_value=CLAIM_TXID)
    else:
        lnw.broadcast_raw_transaction = broadcast
    sm.lnwatcher = lnw

    fake_tx = MagicMock()
    fake_tx.txid.return_value = CLAIM_TXID
    sm._create_and_sign_claim_tx = MagicMock(return_value=fake_tx)
    sm._has_ln_commitment = lambda s: True
    sm._payment_parked = lambda s: True
    return sm


class TestSpendingTxidStamping:
    async def test_success_stamps_spending_txid(self):
        sm = _mk_sm()
        swap = _mk_swap()
        await sm._claim_swap(swap)
        assert swap.spending_txid == CLAIM_TXID
        # the forensic intent marker persisted pre-broadcast (#22 F10)
        assert swap.claim_intent_txid == CLAIM_TXID
        sm.db.write.assert_called()

    async def test_broadcast_failure_leaves_spending_txid_none(self):
        """#54: witness-invalid (or any) broadcast failure must NOT mark
        the swap in flight — the retry state stays observable to the
        client instead of 'already in flight' forever."""
        boom = AsyncMock(side_effect=BitcoinCoreRPCError(
            'sendrawtransaction RPC error: bad-witness-nonstandard'))
        sm = _mk_sm(broadcast=boom)
        swap = _mk_swap()
        await sm._claim_swap(swap)  # must not raise (drivers retry)
        assert swap.spending_txid is None
        assert swap.claim_intent_txid == CLAIM_TXID  # intent persisted
        errs = [c.args[0] for c in sm.logger.error.call_args_list]
        assert any('error broadcasting claim tx' in m for m in errs)

    async def test_failed_broadcast_retries_next_pass(self):
        boom = AsyncMock(side_effect=BitcoinCoreRPCError('txn-mempool-conflict'))
        sm = _mk_sm(broadcast=boom)
        swap = _mk_swap()
        await sm._claim_swap(swap)
        await sm._claim_swap(swap)
        assert sm._create_and_sign_claim_tx.call_count == 2


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


class TestStampingSourceContract:
    def test_marker_stamped_after_broadcast_only(self):
        code = _code_only(_plugin / "submarine_swaps.py")
        bcast = code.index("await self.lnwatcher.broadcast_raw_transaction")
        stamp = code.index("swap.spending_txid = txid")
        assert stamp > bcast, \
            "spending_txid must be assigned only after a successful broadcast (#54)"
        # and the addswapinvoice gate still consumes the same field
        gate = code.index("'swap already in flight'")
        gate_check = code.index("if swap.spending_txid is not None:")
        assert gate > gate_check
