"""Issue #44 regression suite: a transient bitcoind RPC blip must NEVER
exit the plugin. Live 2026-08-31 18:09Z, cln-swap-mutinynet: routine
`docker compose stop bitcoind-mutinynet` (the #78 datadir repair) put the
backend mid-stop exactly when a monitoring pass called is_up_to_date —
BitcoinCoreRPCError('...All connection attempts failed') escaped, lightningd
logged 'Killing plugin: exited during normal operation', and the node ran
headless (no offers, no swaps, no swapprovider-health) until a human
noticed. Worse (issue comment): the deferred htlc_accepted responses were
lost with the process, so parked HTLCs rode to their own CLTV (~22h).

The class-fix contract (mirrors #60 for the esplora path):
1. monitoring_loop: RPC failures retry every 10s with ERROR logs (existed);
   recovery now logs a WARN — one visible line on EACH side of the outage.
2. _claim_swap's is_up_to_date seam treats unavailability as
   not-up-to-date (WARN + skip + retry next tick), never a raise.
3. _init's sync-wait loop waits out an RPC blip like an unsynced chain
   (WARN + retry) instead of letting the raise kill plugin startup.

Run: python3 -m pytest tests/test_issue_44_rpc_blip.py -v
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin import bitcoin_core_rpc as bcr_mod  # noqa: E402
from plugin import chain_monitor as cm_mod  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinCoreRPC, BitcoinCoreRPCError  # noqa: E402
from plugin.chain_monitor import ChainMonitor  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402

_real_asyncio = asyncio

# the live error string, verbatim from the 2026-08-31 crash
BLIP = BitcoinCoreRPCError(
    "ChainMonitor is_up_to_date: Could not get blockchain info: "
    "All connection attempts failed")


class _AsyncioNoSleep:
    """Delegates to asyncio except sleep, which is instant — lets the
    forever-loops run at test speed (same shim as test_fail_loud)."""

    def __getattr__(self, name):
        return getattr(_real_asyncio, name)

    @staticmethod
    async def sleep(_seconds):
        await _real_asyncio.sleep(0.005)


def _monitor() -> ChainMonitor:
    # built via __new__: sibling tests stub sys.modules['bitcoinrpc']
    # before this module imports, so BitcoinCoreRPC.__init__ cannot run
    # here — set exactly the state monitoring_loop/run use
    mon = object.__new__(ChainMonitor)
    mon.callbacks = {}
    mon.monitoring_task = None
    mon._logger = MagicMock()
    return mon


async def _drive_until(task, cond, limit=400):
    for _ in range(limit):
        if cond():
            break
        await _real_asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(_real_asyncio.CancelledError):
        await task


class TestMonitoringLoopSurvivesRpcBlip:
    async def test_is_up_to_date_raise_in_callback_keeps_loop_alive(self, monkeypatch):
        """#44 acceptance: is_up_to_date raising connection-failed inside
        the monitoring loop → plugin still alive on the next tick."""
        monkeypatch.setattr(cm_mod, "asyncio", _AsyncioNoSleep())
        mon = _monitor()
        seq = iter([100, 101, 102, 102])

        async def scripted_height():
            return next(seq)

        mon.get_local_height = scripted_height
        mon.note_rpc_failure = lambda e: False
        calls = []

        async def cb():
            calls.append(1)
            if len(calls) == 1:
                # the live class: _claim_swap → is_up_to_date → raise
                raise BLIP

        mon.callbacks["tb1qfake"] = cb
        task = _real_asyncio.create_task(mon.monitoring_loop())
        await _drive_until(task, lambda: len(calls) >= 2)
        assert len(calls) == 2, "callback must fire again on the next block"
        assert task.cancelled(), "loop ended by OUR cancel, never by a death"
        errs = [c.args[0] for c in mon._logger.error.call_args_list]
        assert any("Error in chain callback" in m for m in errs)
        assert any("All connection attempts failed" in m for m in errs)

    async def test_recovery_logs_warn_after_degraded_passes(self, monkeypatch):
        """#44 acceptance: a WARN on each side of the outage — the ERROR
        per degraded pass (existed) plus a recovery WARN when the backend
        returns."""
        monkeypatch.setattr(cm_mod, "asyncio", _AsyncioNoSleep())
        mon = _monitor()
        seq = iter([RuntimeError("bitcoind temporarily down"),
                    RuntimeError("bitcoind temporarily down"),
                    100, 101, 101])

        async def scripted_height():
            v = next(seq)
            if isinstance(v, Exception):
                raise v
            return v

        mon.get_local_height = scripted_height
        mon.note_rpc_failure = lambda e: False
        fired = []

        async def cb():
            fired.append(1)

        mon.callbacks["tb1qfake"] = cb
        task = _real_asyncio.create_task(mon.monitoring_loop())
        await _drive_until(task, lambda: bool(fired))
        assert fired == [1], "monitoring resumed and fired on the new block"
        errs = [c.args[0] for c in mon._logger.error.call_args_list]
        assert len(errs) == 2, "one ERROR per degraded pass"
        warns = [c.args[0] for c in mon._logger.warning.call_args_list]
        assert any("recovered after 2 degraded pass(es) (#44)" in m
                   for m in warns), warns
        assert task.cancelled(), "loop ended by OUR cancel, never by a death"


class TestClaimSwapSeam:
    async def test_rpc_blip_is_skip_not_raise(self):
        """The is_up_to_date call inside _claim_swap must degrade to a
        skip (WARN + return), so no driver can carry the raise out."""
        sm = SwapManager.__new__(SwapManager)
        sm.logger = MagicMock()
        sm.lnwatcher = MagicMock()
        sm.lnwatcher.is_up_to_date = AsyncMock(side_effect=BLIP)
        swap = SwapData(
            is_reverse=True, locktime=5000, onchain_amount=21181,
            lightning_amount=20000, redeem_script=b"\x51" * 10,
            preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
            lockup_address="tb1qfake", receive_address="", funding_txid=None,
            spending_txid=None, is_redeemed=False)
        swap._payment_hash = (b"\xbb" * 32).hex()
        # must not raise — that is the whole bug
        await sm._claim_swap(swap)
        warns = [c.args[0] for c in sm.logger.warning.call_args_list]
        assert any("#44" in m and "bitcoind RPC unavailable" in m
                   for m in warns), warns
        # and the pass was skipped before any chain-state reads
        sm.lnwatcher.get_addr_outputs.assert_not_called()


class TestInitSyncWaitSurvivesRpcBlip:
    async def test_blip_during_sync_wait_retries_not_dies(self, monkeypatch):
        """bitcoind restarting while the plugin waits for chain sync is an
        ops blip (#78 sequence), not an init failure — _init must keep
        waiting instead of letting the raise kill plugin startup."""
        monkeypatch.setattr(bcr_mod, "asyncio", _AsyncioNoSleep())
        mon = object.__new__(BitcoinCoreRPC)
        mon.iface = MagicMock()  # _init's entry assert only
        mon._wallet_name = "cln-subswapplugin"
        mon._logger = MagicMock()
        mon._chain_lookup_mode = "esplora"  # skips the txindex check
        mon._iface_fail_streak = 0
        mon._test_connection = AsyncMock()
        mon._create_or_load_wallet = AsyncMock()
        mon._validate_wallet_name = AsyncMock()
        results = iter([BLIP, BLIP, True])

        async def blippy():
            v = next(results)
            if isinstance(v, Exception):
                raise v
            return v

        mon.is_up_to_date = AsyncMock(side_effect=blippy)

        await mon._init()  # must not raise

        assert mon.is_up_to_date.await_count == 3
        warns = [c.args[0] for c in mon._logger.warning.call_args_list]
        assert sum("#44" in m and "RPC unavailable during sync wait" in m
                   for m in warns) == 2, warns
        assert mon._iface_fail_streak == 0, "success rewired the #60 streak"
