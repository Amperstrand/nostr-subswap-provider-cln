"""Audit 2026-09-05 round 2 — P0/P1 pins from the three-lane deep audit.

Every pin is RED-first per repo discipline. Findings verified against the
current tree and (where noted) electrum sibling parity:

  P0-A  _fail_swap cancels the d1 payer hold without gating on
        funding_txid — post-broadcast persist failure / misclassified
        broadcast routes into _fail_swap which cancels parked HTLCs
        while the funding tx is LIVE onchain (payer refunded + client
        claims the lockup = double-get). Fix mirrors F23's record gate
        onto the cancel branch.
  P0-B  REDEEM_AFTER_DOUBLE_SPENT stop-watching lacks electrum's
        preimage gate (electrum submarine_swaps.py:473:
        `if spent_height > 0 and swap.preimage:`). The port early-returns
        + DELETES the d1 swap before preimage extraction whenever the
        plugin was blind >30 blocks after the client's claim confirmed:
        hold never settled → payer HTLCs ride to CLTV → client keeps the
        onchain claim. We lose onchain_amount.
  P0-C  register_address hardcodes timestamp:"now" — the import-loss
        recovery re-register never rescans, so a funded lockup stays
        invisible forever and d1 rides into `expired`, which cancels the
        dispatched hold (P0-A's double-get via a second door).
  P0-D  plugin_htlc_accepted_hook's except answers `continue` after the
        request may already be resolved: (a) accepted-then-persist-fail
        diverges memory (ACCEPTED) from lightningd (failed unknown-hash)
        → escrow funded against HTLCs the payer got refunded; (b)
        fail-then-persist-fail double-set_result kills the pyln dispatch
        thread (crash-loop under datastore outage).
  P1-E  run_nostr_server calls server_update_pairs() unguarded — a
        transient listfunds/feerates blip at the 30s/600s tick kills
        the task → taskgroup escalation → #16 hard exit (restart storm).
        publish_offer in the SAME loop is wrapped; this call is not.
  P1-F  the #28 restart re-registration is dead code for d1:
        main_loop gates on `swap.registered` whose only writer is the
        d2 phase-2 handler — every restart strands in-flight d1 holds
        until the #80 watchdog cancels them (~2x expiry later).
  P2-G  _finish_normal_swap .settle on a hold deleted by a racing
        _fail_swap → AttributeError retried every pass forever.

Run: python3 -m pytest tests/test_audit_p0_20260905.py -v
"""
import asyncio
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
from plugin.bitcoin_core_rpc import BitcoinCoreRPC  # noqa: E402

PLUGIN_DIR = _plugin


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


def _d1_swap(funding_txid=None, preimage=None) -> SwapData:
    swap = SwapData(
        is_reverse=False, locktime=2000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=preimage, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qd1", receive_address="", funding_txid=funding_txid,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = ("cc" * 32)
    return swap


def _sm(**attrs) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.prepayments = {}
    sm.config = SimpleNamespace(sweep_grace_blocks=288)
    sm.lnworker = MagicMock()
    sm.lnworker._hold_invoice_callbacks = {}
    sm.lnworker.get_hold_invoice = MagicMock(return_value=None)
    sm.lnworker.get_preimage = MagicMock(return_value=None)
    sm.lnworker.get_payment_statuses = MagicMock(return_value=[])
    sm.lnworker._rpc = MagicMock()
    sm.lnworker._rpc.listpays = MagicMock(return_value={"pays": []})
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1100)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.is_up_to_date = AsyncMock(return_value=True)
    for k, v in attrs.items():
        setattr(sm, k, v)
    return sm


# --------------------------------------------------------------- P0-A
class TestFailSwapFundingGate:
    def test_post_broadcast_failure_must_not_cancel_payer_hold(self):
        """P0-A: funding_txid stamped + broadcast happened (persist or
        misclassified failure) — the payer's parked HTLCs must NOT be
        cancelled while our funding tx is live onchain."""
        swap = _d1_swap(funding_txid="f" * 64)
        hold = MagicMock(name="payer hold")
        sm = _sm()
        sm.swaps = {swap._payment_hash: swap}
        sm.lnworker.get_hold_invoice = MagicMock(
            side_effect=lambda ph: hold if ph == swap.payment_hash else None)
        sm._fail_swap(swap, "funding tx failed: datastore write error")
        hold.cancel_all_htlcs.assert_not_called(), (
            "P0-A: _fail_swap cancelled the payer hold although the "
            "funding tx is live (funding_txid set) — payer refunded + "
            "client claims = double-get")

    def test_pre_broadcast_failure_still_cancels(self):
        """Sanity: no funding onchain → cancelling the hold is the R5
        correct behavior (unchanged by the fix)."""
        swap = _d1_swap(funding_txid=None)
        hold = MagicMock(name="payer hold")
        sm = _sm()
        sm.swaps = {swap._payment_hash: swap}
        sm.lnworker.get_hold_invoice = MagicMock(
            side_effect=lambda ph: hold if ph == swap.payment_hash else None)
        sm._fail_swap(swap, "funding tx failed: fundpsbt starvation")
        hold.cancel_all_htlcs.assert_called_once()


# --------------------------------------------------------------- P0-B
class TestRedeemGatePreimageParity:
    def _manager_with_old_spend(self):
        """d1 swap whose lockup was claimed by the client long ago
        (spent_height far in the past), preimage NOT yet extracted."""
        swap = _d1_swap(preimage=None)
        sm = _sm()
        sm.swaps = {swap._payment_hash: swap}

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

        txin = SimpleNamespace(
            prevout=_Prevout(), value_sats=lambda: 21181,
            block_height=900, spent_height=1000, spent_txid="d" * 64)
        sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=[txin])
        sm.lnwatcher.get_tx_height = AsyncMock(
            return_value=SimpleNamespace(conf=3))
        sm.lnwatcher.get_transaction = AsyncMock(
            return_value=MagicMock(name="claim tx"))
        sm.extract_preimage = MagicMock(return_value=bytes(range(32)))
        sm._finish_normal_swap = MagicMock()
        sm.delete_finished_reverse_swap = MagicMock()
        return sm, swap

    def test_old_spend_without_preimage_must_extract_not_delete(self):
        """P0-B (electrum submarine_swaps.py:473 parity): the
        stop-watching branch must NOT fire while the preimage is still
        unextracted — the swap record must survive and extraction must
        be attempted so the parked payer HTLCs get settled."""
        sm, swap = self._manager_with_old_spend()
        asyncio.run(sm._claim_swap(swap))
        sm.delete_finished_reverse_swap.assert_not_called(), (
            "P0-B: swap deleted via the REDEEM branch before preimage "
            "extraction — payer HTLCs ride to CLTV, client keeps the claim")
        assert not swap.is_redeemed, "P0-B: is_redeemed set pre-extraction"
        assert swap._payment_hash in sm.swaps, "P0-B: record dropped"
        sm.lnwatcher.get_transaction.assert_called(), (
            "P0-B: preimage extraction was never attempted")

    def test_old_spend_with_preimage_may_stop_watching(self):
        """Sanity: extraction already happened (preimage present) — the
        REDEEM branch is the correct cleanup (d2/finished shape)."""
        swap = _d1_swap(preimage="aa" * 32)
        sm = _sm()
        sm.swaps = {swap._payment_hash: swap}

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

        txin = SimpleNamespace(
            prevout=_Prevout(), value_sats=lambda: 21181,
            block_height=900, spent_height=1000, spent_txid="d" * 64)
        sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=[txin])
        sm.lnwatcher.get_tx_height = AsyncMock(
            return_value=SimpleNamespace(conf=3))
        sm.delete_finished_reverse_swap = MagicMock()
        asyncio.run(sm._claim_swap(swap))
        sm.delete_finished_reverse_swap.assert_called_once()


# --------------------------------------------------------------- P0-C
class TestRegisterAddressRescan:
    def _rpc(self):
        rpc = BitcoinCoreRPC.__new__(BitcoinCoreRPC)
        rpc.logger = MagicMock()
        rpc.iface = MagicMock()
        rpc.iface.acall = AsyncMock(return_value=[{"success": True}])
        return rpc

    def test_recovery_re_register_can_rescan(self):
        """P0-C: register_address must accept an explicit rescan
        timestamp; the import-loss recovery passes one so a funded
        lockup becomes visible again instead of riding to `expired`."""
        rpc = self._rpc()
        asyncio.run(rpc.register_address("tb1qfake", rescan_from=0))
        params = rpc.iface.acall.call_args.kwargs["params"]
        assert params[0][0]["timestamp"] == 0, (
            "P0-C: register_address has no rescan path — hardcoded "
            "timestamp 'now' blinds the recovered watch forever")

    def test_default_still_avoids_rescan(self):
        """Sanity: fresh addresses keep the cheap 'now' import."""
        rpc = self._rpc()
        asyncio.run(rpc.register_address("tb1qfake"))
        params = rpc.iface.acall.call_args.kwargs["params"]
        assert params[0][0]["timestamp"] == "now"

    def test_recovery_seam_passes_rescan(self):
        """The import-loss recovery call in _claim_swap must request the
        rescan (source contract — executable code only)."""
        code = _code_only(PLUGIN_DIR / "submarine_swaps.py")
        assert re.search(
            r"register_address\(\s*swap\.lockup_address,\s*rescan_from=", code), (
            "P0-C: the 'imported before' recovery re-registers without a "
            "rescan — the funded lockup stays invisible")


# --------------------------------------------------------------- P0-D
class _FakeRequest:
    """pyln Request stand-in: records set_result, second call raises
    like pyln's 'Cannot set the result of a request that is not pending'."""

    def __init__(self):
        self.results = []

    def set_result(self, value):
        if self.results:
            raise RuntimeError(
                "Cannot set the result of a request that is not pending")
        self.results.append(value)


class TestHookExceptPath:
    def _cln(self, invoice):
        from plugin.cln_lightning import CLNLightning
        db = MagicMock()
        db.get_dict.side_effect = lambda k: {}
        db.write = MagicMock()
        plugin_instance = MagicMock()
        plugin_instance.plugin.rpc = MagicMock()
        plugin_instance.derive_secret = lambda label: b"\x11" * 32
        cln = CLNLightning(plugin_instance=plugin_instance,
                           config=SimpleNamespace(), db=db, logger=MagicMock())
        key = invoice.payment_hash.hex()
        cln._hold_invoices[key] = invoice
        cln.get_hold_invoice = lambda ph: cln._hold_invoices.get(ph.hex())
        decoded = {
            "min_final_cltv_expiry": 18,
            "payment_secret": "ab" * 32,
        }
        cln._rpc.decode = MagicMock(return_value=decoded)
        return cln

    @staticmethod
    def _htlc_dict(amount_msat=100000000):
        return {"short_channel_id": "103x1x0", "id": 1,
                "amount_msat": amount_msat,
                "cltv_expiry_relative": 144,
                "payment_hash": "ab" * 32}

    def _invoice(self):
        from plugin.invoices import HoldInvoice, InvoiceState
        inv = HoldInvoice(payment_hash=b"\xab" * 32, bolt11="lnbcrt1x",
                          amount_msat=100000000, expiry=3600)
        inv.funding_status = InvoiceState.UNFUNDED
        return inv

    def test_accepted_htlc_persist_fail_must_not_answer_continue(self):
        """P0-D(a): HTLC accepted in memory, update_invoice (datastore
        write) fails — answering `continue` makes lightningd fail the
        unknown-hash HTLC while memory counts it funded → escrow funded
        against refunded HTLCs. The hook must answer `fail` and roll the
        in-memory add back so memory mirrors lightningd's verdict."""
        from plugin.invoices import InvoiceState
        cln = self._cln(self._invoice())
        cln.update_invoice = MagicMock(side_effect=RuntimeError("datastore down"))
        request = _FakeRequest()
        onion = {"payment_secret": "ab" * 32}
        cln.plugin_htlc_accepted_hook(onion, self._htlc_dict(), request, None)
        assert request.results, "hook must answer exactly once"
        verdict = request.results[0]
        assert verdict.get("result") == "fail", (
            f"P0-D(a): hook answered {verdict!r} after a persistence "
            f"failure — memory says funded, lightningd failed the HTLC")
        invoice = cln.get_hold_invoice(b"\xab" * 32)
        unaccepted = [h for h in invoice.incoming_htlcs
                      if h.state.name == "ACCEPTED"]
        assert unaccepted == [], (
            "P0-D(a): the accepted-in-memory HTLC was not rolled back "
            "after lightningd was told to fail it")

    def test_failed_htlc_persist_fail_must_not_double_respond(self):
        """P0-D(b): validation failed the HTLC (request already
        resolved), then update_invoice raises — the except's second
        set_result must not escape (dispatch-thread death class)."""
        cln = self._cln(self._invoice())
        cln.update_invoice = MagicMock(side_effect=RuntimeError("datastore down"))
        request = _FakeRequest()
        onion = {"payment_secret": "WRONG"}  # fails the payment-secret check
        try:
            cln.plugin_htlc_accepted_hook(onion, self._htlc_dict(), request, None)
        except RuntimeError as e:
            if "not pending" in str(e):
                pytest.fail(
                    "P0-D(b): double set_result escaped the hook — this "
                    "exact class kills the pyln dispatch thread live")
            raise
        assert len(request.results) == 1, (
            "P0-D(b): hook answered more than once")
        assert request.results[0].get("result") == "fail"

    def test_healthy_path_parks_without_answering(self):
        """Sanity: valid HTLC, no persistence failure — the HTLC parks
        (deferral by design), stored ACCEPTED, nothing answered early."""
        cln = self._cln(self._invoice())
        cln.update_invoice = MagicMock()
        request = _FakeRequest()
        onion = {"payment_secret": "ab" * 32}
        cln.plugin_htlc_accepted_hook(onion, self._htlc_dict(), request, None)
        invoice = cln.get_hold_invoice(b"\xab" * 32)
        assert len(invoice.incoming_htlcs) == 1, "valid HTLC must park"
        parked = next(iter(invoice.incoming_htlcs))
        assert parked.state.name == "ACCEPTED"
        assert request.results == [], (
            "a parked HTLC is a deferral — answered only by settle/fail "
            "later, not at hook time")


# --------------------------------------------------------------- P1-E
class TestPairsUpdateGuarded:
    def test_server_update_pairs_call_is_wrapped(self):
        """P1-E: the pairs update at the nostr cadence must be inside
        the same withdraw-and-retry protection as publish_offer — an
        RPC blip there currently kills the whole plugin (source
        contract, executable code only)."""
        code = _code_only(PLUGIN_DIR / "submarine_swaps.py")
        assert re.search(
            r"try:\s*\n\s+self\.server_update_pairs\(\)", code), (
            "P1-E: run_nostr_server calls server_update_pairs() bare — "
            "a transient listfunds/feerates blip escalates to the #16 "
            "hard exit")


# --------------------------------------------------------------- P1-F
class TestD1RestartReregistration:
    def test_main_loop_gate_does_not_require_registered_flag(self):
        """P1-F: `swap.registered` is only ever set on the d2 phase-2
        path, so gating the d1 (#28) restart re-registration on it is
        provably dead code — every restart strands in-flight d1 holds
        until the #80 watchdog cancels them (source contract)."""
        code = _code_only(PLUGIN_DIR / "submarine_swaps.py")
        assert not re.search(
            r"swap\.registered and swap\.funding_txid is None", code), (
            "P1-F: main_loop's d1 re-registration still requires the "
            "never-set `registered` flag — the #28 fix is dead code")


# --------------------------------------------------------------- P2-G
class TestFinishNormalSwapMissingHold:
    def test_missing_hold_is_terminal_not_crash(self):
        """P2-G: hold already deleted by a racing _fail_swap —
        _finish_normal_swap must terminal-log and drop the record, not
        AttributeError-loop forever."""
        swap = _d1_swap(preimage="aa" * 32)
        sm = _sm()
        sm.swaps = {swap._payment_hash: swap}
        sm.lnworker.get_hold_invoice = MagicMock(return_value=None)
        try:
            sm._finish_normal_swap(swap)
        except AttributeError as e:
            pytest.fail(f"P2-G: None.settle crash-loop: {e}")
        assert swap._payment_hash not in sm.swaps, (
            "P2-G: record must be dropped when the hold is gone")
        assert any("hold" in str(c.args[0]).lower()
                   for c in sm.logger.error.call_args_list), (
            "P2-G: the terminal state must be visible at ERROR")
