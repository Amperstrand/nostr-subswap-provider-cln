"""issue #24 option E (FUNDING-GATE-COMPAT-MEMO, operator-adopted) unit
matrix: the #12 funding-gate parking is bounded by an M-block timer
anchored at addswapinvoice, discharged early when the lockup becomes
visible in MEMPOOL (pay without waiting for a confirmation; the claim
broadcast stays >=1-conf, R1), ended at M in fail (default) or pay
(FUNDING_GATE_ON_TIMEOUT_BEHAVIOR) mode, with a dead client invoice
failing via EXPIRY before any M timeout (#25 ordering).

The deadlock this resolves (e2e-proof-37.txt section 4 F1): a stock
electrum client registers a hold invoice and broadcasts its lockup only
inside the hold callback (i.e. when our payment HTLC arrives), while the
gate parks the payment until a lockup is observed — mutual wait. Under
option E the mutual wait becomes a bounded clean failure at M (memo:
"the provider doesn't lose funds, and the client can retry with a new
swap"); an honest lockup-first client is paid the moment the lockup
shows in mempool, sub-block.

Run: python3 -m pytest tests/test_funding_gate_option_e.py -v
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
import sys
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402


def _d2_swap() -> SwapData:
    # the deadlock direction: server-side reverse (createnormalswap ->
    # create_reverse_swap, is_reverse=True); the preimage is ours from
    # creation, exactly like a live d2 registration
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False, registered=True)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


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


def _txin(value=21181, conf=0):
    return SimpleNamespace(
        prevout=_Prevout(), value_sats=lambda: value,
        block_height=None, spent_height=None, spent_txid=None)


def _expired_invoice(expired: bool):
    inv = SimpleNamespace(has_expired=lambda: expired)
    return inv


async def watch_pass_at(sm: SwapManager, height: int):
    """One option-E watch pass with the chain height pinned."""
    sm.wallet.get_local_height = AsyncMock(return_value=height)
    await sm._funding_gate_watch_pass()


def _manager(swap: SwapData, *, height=4900, conf=0, txins=None,
             invoice=None, m_blocks=30, on_timeout="fail") -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {swap._payment_hash: swap}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = {swap._payment_hash}
    sm._funding_gate_deadline = {}
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm.config = SimpleNamespace(sweep_grace_blocks=288,
                                funding_gate_timeout_blocks=m_blocks,
                                funding_gate_on_timeout=on_timeout)
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm._create_and_sign_claim_tx = MagicMock(
        return_value=MagicMock(txid=lambda: "f" * 64))
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=height)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.is_up_to_date = AsyncMock(return_value=True)
    sm.lnwatcher.broadcast_raw_transaction = AsyncMock(return_value="f" * 64)
    sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=txins or [])
    sm.lnwatcher.get_tx_height = AsyncMock(
        return_value=SimpleNamespace(conf=conf))
    sm.lnworker = MagicMock()
    sm.lnworker.get_invoice = MagicMock(return_value=invoice)
    sm.lnworker.get_payment_statuses = MagicMock(return_value=[])
    sm.lnworker.get_preimage = MagicMock(return_value=swap.preimage)
    # #26 park-then-claim: payer-side listpays must report parked/
    # settled for the claim to fire in these discharge tests
    sm.lnworker._rpc = MagicMock()
    sm.lnworker._rpc.listpays = MagicMock(
        return_value={"pays": [{"status": "complete"}]})
    return sm


class TestMempoolDischarge:
    async def test_mempool_lockup_pays_without_waiting_for_confirmation(self):
        # Option E core: lockup visible in MEMPOOL (conf=0) -> the gate
        # discharges and the payment is queued immediately; the claim
        # broadcast itself remains >=1-conf gated (R1 non-regression)
        swap = _d2_swap()
        sm = _manager(swap, height=4900, conf=0, txins=[_txin(conf=0)],
                      invoice=_expired_invoice(False))
        await sm._funding_gate_watch_pass()
        assert swap._payment_hash not in sm.invoices_awaiting_funding
        assert sm.invoices_to_pay[swap._payment_hash] == 0
        sm.lnwatcher.broadcast_raw_transaction.assert_not_called()

    async def test_confirmed_lockup_broadcasts_claim(self):
        # after the confirmation the standard claim path fires (R1)
        swap = _d2_swap()
        sm = _manager(swap, height=4900, conf=1, txins=[_txin(conf=1)],
                      invoice=_expired_invoice(False))
        await sm._funding_gate_watch_pass()
        sm.lnwatcher.broadcast_raw_transaction.assert_called_once()

    async def test_discharge_survives_repeated_passes(self):
        # once discharged, further passes neither re-queue nor fail
        swap = _d2_swap()
        sm = _manager(swap, height=4900, conf=0, txins=[_txin(conf=0)],
                      invoice=_expired_invoice(False))
        for _ in range(3):
            await sm._funding_gate_watch_pass()
        assert sm.invoices_to_pay[swap._payment_hash] == 0
        assert swap._payment_hash in sm.swaps


class TestFailAtM:
    async def test_no_lockup_fails_at_exactly_m_not_m_pm_1(self):
        # M=30: anchored at the first evaluation height h0; the fail
        # fires at h0+30 exactly — not h0+29, not h0+31
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=30)
        h0 = 4900
        await watch_pass_at(sm, h0)
        assert swap._payment_hash in sm.invoices_awaiting_funding
        for h in range(h0 + 1, h0 + 30):
            await watch_pass_at(sm, h)
            assert swap._payment_hash in sm.swaps, f"failed early at {h}"
            assert swap._payment_hash in sm.invoices_awaiting_funding
        await watch_pass_at(sm, h0 + 30)
        assert swap._payment_hash not in sm.swaps
        assert swap._payment_hash not in sm.invoices_awaiting_funding
        assert 'funding gate timeout' in sm.logger.warning.call_args.args[0]

    async def test_m_env_override_honored(self):
        # FUNDING_GATE_TIMEOUT_BLOCKS=2 (via config, as from_cln_and_env
        # does) -> the window is 2 blocks, not the memo default 30
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=2)
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4901)
        assert swap._payment_hash in sm.swaps
        await watch_pass_at(sm, 4902)
        assert swap._payment_hash not in sm.swaps

    async def test_failed_swap_unwinds_completely(self):
        # the memo's clean bounded failure: no payment was ever queued,
        # the chain watch and the swap record are gone
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=1)
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4901)
        assert sm.invoices_to_pay == {}
        sm.lnwatcher.remove_callback.assert_called_once_with(swap.lockup_address)
        assert sm.db.write.called

    async def test_block_tick_also_bounds_the_gate(self):
        # degraded mode: even without the watch loop, the ChainMonitor's
        # block-boundary _claim_swap drives the same bounded outcome
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=2)
        await sm._claim_swap(swap)   # anchors at the faked height 4900
        sm.wallet.get_local_height = AsyncMock(return_value=4901)
        await sm._claim_swap(swap)
        assert swap._payment_hash in sm.swaps
        sm.wallet.get_local_height = AsyncMock(return_value=4902)
        await sm._claim_swap(swap)
        assert swap._payment_hash not in sm.swaps


class TestPayAtM:
    async def test_pay_mode_queues_payment_and_keeps_record(self):
        # FUNDING_GATE_ON_TIMEOUT_BEHAVIOR=pay: at M the invoice is paid
        # anyway (bounded jam exposure), the swap is NOT failed
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=2,
                      on_timeout="pay")
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4902)
        assert sm.invoices_to_pay[swap._payment_hash] == 0
        assert swap._payment_hash in sm.swaps
        assert 'paying anyway' in sm.logger.warning.call_args.args[0]


class TestExpiryOrdering:
    async def test_expired_invoice_fails_via_expiry_before_m(self):
        # #25 ordering: a client invoice that dies before M fails as
        # EXPIRED the moment we notice — even when both conditions hold
        # in the same pass, expiry wins
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(True), m_blocks=30)
        await watch_pass_at(sm, 4900)          # anchor + notice
        assert swap._payment_hash not in sm.swaps
        reason = sm.logger.warning.call_args.args[0]
        assert 'expired' in reason and 'funding gate timeout' not in reason

    async def test_live_invoice_at_m_fails_via_timeout(self):
        # the complementary ordering: invoice still live at M -> timeout
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=1)
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4901)
        reason = sm.logger.warning.call_args.args[0]
        assert 'funding gate timeout' in reason

    async def test_missing_invoice_record_uses_timeout_only(self):
        # invoice already deleted (edge): no expiry signal, M still bounds
        swap = _d2_swap()
        sm = _manager(swap, invoice=None, m_blocks=1)
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4901)
        assert swap._payment_hash not in sm.swaps


class TestJamGateNonRegression:
    async def test_no_payment_without_lockup_within_m(self):
        # #12's rationale intact: inside the M window, an invoice with no
        # onchain lockup NEVER triggers a payment attempt
        swap = _d2_swap()
        sm = _manager(swap, invoice=_expired_invoice(False), m_blocks=1000)
        for h in range(4900, 4950):
            await watch_pass_at(sm, h)
        assert sm.invoices_to_pay == {}
        assert swap._payment_hash in sm.swaps

    async def test_underfunded_mempool_output_does_not_discharge(self):
        # issue #7 decoy guard stays load-bearing inside the E path: a
        # sub-onchain_amount mempool output must not pay or fail early
        swap = _d2_swap()
        sm = _manager(swap, conf=0, txins=[_txin(value=546)],
                      invoice=_expired_invoice(False), m_blocks=5)
        await watch_pass_at(sm, 4900)
        await watch_pass_at(sm, 4902)
        assert sm.invoices_to_pay == {}
        assert swap._payment_hash in sm.swaps


class TestSourceContracts:
    def test_watch_loop_registered_in_main_loop(self):
        src = (_plugin / "submarine_swaps.py").read_text()
        assert "self.funding_gate_watch_loop()," in src, (
            "main_loop must spawn the option E funding-gate watcher")

    def test_invoice_expiry_reads_config(self):
        src = (_plugin / "submarine_swaps.py").read_text()
        assert "expiry=expiry_s" in src and "expiry=300" not in src, (
            "d1 invoice expiry must come from INVOICE_EXPIRY_SECONDS "
            "(memo option F), not the hardcoded 300")
