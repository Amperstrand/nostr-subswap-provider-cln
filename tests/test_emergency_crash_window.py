"""Regression tests for the emergency-reserve crash window (plugin #35,
upstream ElementsProject/lightning#9452).

LIVE BUG (2026-08-29 19:28-19:33Z, inr2 cln-swap-signet, five lightningd
cores ~90s apart): utxopsbt with excess_as_change=true SIGABRTs the
DAEMON in change_for_emergency (wallet/reservation.c) whenever

  * the node has anchor channels (keep_emergency_funds is forced on),
  * wallet_has_funds over the UNSELECTED wallet < min-emergency-msat,
  * and the change-from-excess cannot cover the reserve after its own
    fee (0 < change - change_fee < emergency_sat).

The assert after the split branch is algebraically unsatisfiable for any
entering change > 0: change_amount(c0 + fee + needed) = c0 + needed.
Our funding path enters with c0 = excess (excess_as_change=true), so a
wallet near its floor turns a swap funding into a lightningd crash-loop
(restart replays the same wallet state; the plugin's retry cadence minted
five cores in five minutes).

Fix contract (this file): create_transaction REFUSES to call utxopsbt
whenever even selecting EVERYTHING would leave the change under the
emergency reserve plus fee headroom — a clean swap failure (return None)
instead of a daemon abort. The refusal must happen BEFORE any utxopsbt
RPC leaves the process.

Run: python3 -m pytest tests/test_emergency_crash_window.py -v
"""
from pathlib import Path
from unittest.mock import MagicMock

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

import sys
if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))

from plugin.cln_chain import CLNChainWallet  # noqa: E402
from plugin.transaction import PartialTxOutput  # noqa: E402

CANNED_PSBT = (
    "cHNidP8BAF4CAAAAAeTzBs9cErlZKRgOJanUaxqpbXdXAeSW4uW6MgC6qfU5"
    "AAAAAAD9////AQqBAQAAAAAAIlEg5GX1Slw/1RDwGvBGJA+2VE2HKeA2ibj/"
    "d39y742y2glO3AQAAAEAfQIAAAABHPSN4iro4h5ldotHrXNQ6tECTW2LiYW1"
    "/H5GTViFbCMBAAAAAP3///8CwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWty"
    "eNy+cqr+BwAAAAAAIlEg0v0s/9DJsNLCFHWQUbWoNjMPAgPBJC6wcPNUzGo"
    "QVjAv3AQAAQEfwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWtyeNy+cgAA"
)

FREE_P2WPKH = "0014" + "1f" * 20


def _wallet_with_pool(outputs, emergency_sat=25_000):
    rpc = MagicMock()
    rpc.listfunds.return_value = {"outputs": outputs}
    rpc.utxopsbt.return_value = {"psbt": CANNED_PSBT, "excess_msat": 600_000}
    rpc.signpsbt.return_value = {"signed_psbt": CANNED_PSBT}
    wallet = CLNChainWallet(
        plugin_rpc=rpc, config=MagicMock(), logger=MagicMock())
    # pin the reserve reading (listconfigs stays mocked out entirely)
    wallet._min_emergency_sat = emergency_sat
    return wallet, rpc


def _out(sat):
    return PartialTxOutput(scriptpubkey=bytes.fromhex(FREE_P2WPKH), value=sat)


class TestEmergencyCrashWindowGuard:
    def test_refuses_when_change_would_land_in_crash_window(self):
        """THE live counterexample: pool {70k, 20k}, emergency 25k —
        today this passes the #31 accept gate, then utxopsbt selects
        70k for a ~64k ask, leaves ~4k change (< reserve) with a 20k
        unselected rest (< reserve) → lightningd SIGABRT. The guard
        must refuse BEFORE any RPC."""
        wallet, rpc = _wallet_with_pool([
            {"txid": "aa" * 32, "output": 0, "amount_msat": 70_000_000,
             "status": "confirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
            {"txid": "bb" * 32, "output": 0, "amount_msat": 20_000_000,
             "status": "confirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
        ])
        tx = wallet.create_transaction(outputs_without_change=[_out(64_000)],
                                       rbf=True)
        assert tx is None, "the crash-window funding must fail cleanly"
        assert not rpc.utxopsbt.called, \
            "no utxopsbt RPC may leave the process in the crash window — it aborts lightningd"

    def test_funds_when_headroom_clears_the_reserve(self):
        """Healthy wallet: even the max escalation ask leaves the change
        above reserve + fee headroom → the funding proceeds and the
        excess_as_change flag stays (the mitigation is the guard, not
        dropping the flag)."""
        wallet, rpc = _wallet_with_pool([
            {"txid": "aa" * 32, "output": 0, "amount_msat": 200_000_000,
             "status": "confirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
        ])
        tx = wallet.create_transaction(outputs_without_change=[_out(20_000)],
                                       rbf=True)
        assert tx is not None
        assert rpc.utxopsbt.called
        assert rpc.utxopsbt.call_args.kwargs["excess_as_change"] is True

    def test_boundary_exact_headroom_funds(self):
        """free_total - max_ask == emergency + margin exactly → allowed
        (the guard is <, not <=)."""
        # max ask = 20_000 + 1_000 + 3*2_500 = 28_500; need free_total
        # = 28_500 + 25_000 + margin
        margin = CLNChainWallet.FUNDING_FEE_MARGIN_SAT
        free = 28_500 + 25_000 + margin
        wallet, rpc = _wallet_with_pool([
            {"txid": "aa" * 32, "output": 0, "amount_msat": free * 1000,
             "status": "confirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
        ])
        tx = wallet.create_transaction(outputs_without_change=[_out(20_000)],
                                       rbf=True)
        assert tx is not None
        assert rpc.utxopsbt.called

    def test_higher_emergency_floor_tightens_the_guard(self):
        """A raised min-emergency-msat (make-do floor era) must shrink
        the fundable set — the guard reads the reserve, not a constant."""
        margin = CLNChainWallet.FUNDING_FEE_MARGIN_SAT
        free = 200_000_000 // 1000  # 200k sat
        # at emergency 150k: 200k - 28.5k = 171.5k >= 150k + margin?
        # margin >= 21500 → refuse; with default margin 15000 → allowed.
        wallet, rpc = _wallet_with_pool(
            [{"txid": "aa" * 32, "output": 0, "amount_msat": free * 1000,
              "status": "confirmed", "reserved": False,
              "scriptpubkey": FREE_P2WPKH}],
            emergency_sat=150_000)
        tx = wallet.create_transaction(outputs_without_change=[_out(20_000)],
                                       rbf=True)
        if margin > 21_500:
            assert tx is None and not rpc.utxopsbt.called
        else:
            assert tx is not None and rpc.utxopsbt.called
