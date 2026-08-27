"""Heartbeat/liveness surface (audit round 5): issue #23 HealthTracker
beats + F12 error-streak aggregation, the swapprovider-health RPC
(ok|degraded|dead verdict), and the pyln pipe late-death watchdog.
Kill-injection style like test_fail_loud.py: os._exit always
monkeypatched, nothing here can kill the test runner.

Run: python3 -m pytest tests/test_health.py -v
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin import cln_swap_provider as csp_mod  # noqa: E402
from plugin import submarine_swaps as ss  # noqa: E402
from plugin.cln_swap_provider import CLNSwapProvider  # noqa: E402
from plugin.cln_plugin import CLNPlugin  # noqa: E402
from plugin.constants import PAYMENT_INFLIGHT_LOCK  # noqa: E402
from plugin.health import (build_report, tracker,  # noqa: E402
                           CHAIN_MONITOR, NOSTR_CONSUMER, OFFER_PUBLISHER,
                           PAYMENT_LOOP, PYLN_THREAD)
from plugin.invoices import InvoiceState  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402

_real_asyncio = asyncio


class _AsyncioNoSleep:
    """Delegates everything to asyncio except sleep — test-speed loops."""
    def __getattr__(self, name):
        return getattr(_real_asyncio, name)

    @staticmethod
    async def sleep(_seconds):
        await _real_asyncio.sleep(0.005)


@pytest.fixture(autouse=True)
def _fresh_tracker():
    tracker.reset()
    yield
    tracker.reset()


def _healthy_beats():
    tracker.beat(CHAIN_MONITOR, detail="height=101")
    tracker.beat(PAYMENT_LOOP, detail="0 tracked")
    tracker.beat(OFFER_PUBLISHER, detail="published")
    tracker.beat(NOSTR_CONSUMER, detail="last event abcdef12…")
    tracker.beat(PYLN_THREAD)
    tracker.note_nostr_up()


def _sm(**attrs) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.is_initialized = asyncio.Event()
    sm.lnworker = MagicMock()
    sm.lnworker.get_hold_invoice = MagicMock(return_value=None)
    sm.lnworker.get_invoice = MagicMock(return_value=None)
    for k, v in attrs.items():
        setattr(sm, k, v)
    return sm


def _provider(sm=None, lnworker=None) -> CLNSwapProvider:
    p = CLNSwapProvider()
    p.plugin_handler = SimpleNamespace(thread_alive=lambda: True)
    p.config = SimpleNamespace(sweep_grace_blocks=2)
    p.swap_manager = sm
    p.cln_lightning = lnworker
    p.json_db = SimpleNamespace(
        storage=SimpleNamespace(last_generation=7,
                                last_write_monotonic=time.monotonic() - 3))
    return p


class TestHealthyVerdict:
    def test_all_subsystems_alive_verdict_ok(self):
        _healthy_beats()
        report = build_report(_provider())
        assert report["verdict"] == "ok"
        assert report["reasons"] == []
        assert all(s["alive"] for s in report["subsystems"].values())
        assert all(s["error_streak"] == 0 for s in report["subsystems"].values())
        assert report["nostr_mode"] == "up"
        assert report["sweep_grace_blocks"] == 2
        assert report["datastore"] == {"generation": 7,
                                       "last_write_ms_ago": report["datastore"]["last_write_ms_ago"]}
        # json-serializable end to end (the RPC wire format)
        json.dumps(report)

    def test_missing_parts_report_starting_not_dead(self):
        report = build_report(CLNSwapProvider())
        assert report["verdict"] == "ok"  # inside the startup grace
        assert report["grace_held_swaps"] is None


class TestNostrKillDegraded:
    async def test_publish_failure_withdraws_and_degrades(self, monkeypatch):
        events = {"publishes": 0}

        class FakeTransport:
            def __init__(self, config, sm):
                self.sm = sm
                self.is_connected = asyncio.Event()
                self.dead = asyncio.Event()

            def __enter__(self):
                self.is_connected.set()
                return self

            def __exit__(self, *a):
                self.sm.is_initialized.clear()

            async def publish_offer(self):
                events["publishes"] += 1
                raise RuntimeError("relay gone")  # every publish fails

        monkeypatch.setattr(ss, "NostrTransport", FakeTransport)
        monkeypatch.setattr(ss, "asyncio", _AsyncioNoSleep())
        sm = _sm()
        sm.config = SimpleNamespace(nostr_relays=[])
        sm.server_update_pairs = MagicMock()
        sm._max_amount = 100
        server = _real_asyncio.create_task(sm.run_nostr_server())
        for _ in range(400):
            if tracker.nostr_mode == "down":
                break
            await _real_asyncio.sleep(0.005)
        server.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await server

        assert tracker.nostr_mode == "down"  # withdrawal mirrored
        report = build_report(_provider())
        assert report["verdict"] == "degraded"
        assert any("nostr: down" in r for r in report["reasons"])
        assert any("offer-publisher" in r and "consecutive errors" in r
                   for r in report["reasons"])  # F12 streak surfaced
        assert not report["subsystems"]["nostr-consumer"]["alive"]

    async def test_consumer_last_seen_grows_after_death(self, monkeypatch):
        t, sent = _stub_transport(monkeypatch)
        await t.check_direct_messages()
        first = build_report(_provider())["subsystems"][NOSTR_CONSUMER]
        await _real_asyncio.sleep(0.05)
        second = build_report(_provider())["subsystems"][NOSTR_CONSUMER]
        assert first["last_seen_ms_ago"] is not None
        assert second["last_seen_ms_ago"] > first["last_seen_ms_ago"]
        assert len(sent) == 1  # junk skipped, the real DM answered

    async def test_consumer_dispatch_error_counts_streak(self, monkeypatch):
        t, sent = _stub_transport(monkeypatch, send_boom=True)
        await t.check_direct_messages()
        report = build_report(_provider())
        assert report["subsystems"][NOSTR_CONSUMER]["error_streak"] == 1
        assert any("nostr-consumer" in r and "consecutive errors" in r
                   for r in report["reasons"])


class TestChainMonitorHeartbeat:
    async def test_pass_beats_with_height_detail(self, monkeypatch):
        from plugin.chain_monitor import ChainMonitor
        mon = object.__new__(ChainMonitor)
        mon.callbacks = {}
        mon._logger = MagicMock()
        seq = iter([100, 101, 101])

        async def height():
            return next(seq)

        mon.get_local_height = height
        task = _real_asyncio.create_task(mon.monitoring_loop())
        for _ in range(200):
            if tracker._beats.get(CHAIN_MONITOR) is not None:
                break
            await _real_asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await task
        assert "height=" in tracker._details[CHAIN_MONITOR]

    async def test_rpc_failure_drives_error_streak_degraded(self, monkeypatch):
        from plugin import chain_monitor as cm_mod
        from plugin.chain_monitor import ChainMonitor
        monkeypatch.setattr(cm_mod, "asyncio", _AsyncioNoSleep())
        mon = object.__new__(ChainMonitor)
        mon.callbacks = {}
        mon._logger = MagicMock()

        async def down():
            raise RuntimeError("bitcoind down")

        mon.get_local_height = down
        task = _real_asyncio.create_task(mon.monitoring_loop())
        for _ in range(300):
            if tracker._error_streaks.get(CHAIN_MONITOR, 0) >= 2:
                break
            await _real_asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await task
        # r4 RETRY policy intact (loop ended by OUR cancel) + F12 visible
        report = build_report(_provider())
        assert report["verdict"] == "degraded"
        assert any("chain-monitor" in r and "consecutive errors" in r
                   for r in report["reasons"])
        assert report["subsystems"][CHAIN_MONITOR]["alive"]  # retrying, not dead

    async def test_wedged_loop_reads_dead_before_fatal(self, monkeypatch):
        """Snapshot just before the policy fires must show the stale
        chain heartbeat (wedged > dead_after)."""
        _healthy_beats()
        tracker._beats[CHAIN_MONITOR] = time.monotonic() - 120  # wedged
        report = build_report(_provider())
        assert report["verdict"] == "dead"
        assert report["subsystems"][CHAIN_MONITOR]["alive"] is False
        assert report["subsystems"][CHAIN_MONITOR]["last_seen_ms_ago"] >= 120_000
        assert any("wedged" in r for r in report["reasons"])

    async def test_escaped_death_still_fires_r4_fatal_policy(self, monkeypatch):
        from plugin.bitcoin_core_rpc import BitcoinCoreRPC
        from plugin.chain_monitor import ChainMonitor
        monkeypatch.setattr(BitcoinCoreRPC, "_init", AsyncMock(return_value=None))
        exits = []
        monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
        mon = object.__new__(ChainMonitor)
        mon.callbacks = {}
        mon._logger = MagicMock()

        class InjectedBaseDeath(BaseException):
            pass

        async def dead_rpc():
            raise InjectedBaseDeath("nuked")

        mon.get_local_height = dead_rpc
        await mon.run()
        for _ in range(100):
            if exits:
                break
            await _real_asyncio.sleep(0.01)
        assert exits == [1], "r4 fatal policy must keep firing (unchanged)"


class TestPylnWatchdog:
    async def test_dead_pipe_routes_to_fatal_policy(self, monkeypatch):
        fatal = []
        monkeypatch.setattr(csp_mod, "fatal_exit",
                            lambda msg, logger=None: fatal.append(msg))
        monkeypatch.setattr(csp_mod, "PYLN_WATCHDOG_INTERVAL_SEC", 0.01)
        provider = CLNSwapProvider()
        provider.plugin_handler = SimpleNamespace(thread_alive=lambda: False)
        provider.logger = MagicMock()
        task = _real_asyncio.create_task(provider._pyln_pipe_watchdog())
        for _ in range(100):
            if fatal:
                break
            await _real_asyncio.sleep(0.01)
        task.cancel()
        assert len(fatal) == 1 and "dispatch thread died" in fatal[0]
        assert PYLN_THREAD in tracker._beats  # beat landed before the probe

    async def test_alive_pipe_just_beats(self, monkeypatch):
        monkeypatch.setattr(csp_mod, "PYLN_WATCHDOG_INTERVAL_SEC", 0.01)
        provider = CLNSwapProvider()
        provider.plugin_handler = SimpleNamespace(thread_alive=lambda: True)
        task = _real_asyncio.create_task(provider._pyln_pipe_watchdog())
        for _ in range(100):
            if tracker._beats.get(PYLN_THREAD) is not None:
                break
            await _real_asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await task
        assert build_report(_provider())["subsystems"][PYLN_THREAD]["alive"]


class TestHealthRpcDispatch:
    def test_registered_and_served_through_real_pyln_dispatch(self):
        provider = _provider()
        handler = CLNSwapProvider._swapprovider_health_rpc.__get__(provider)
        cln = CLNPlugin(rpc_methods=[("swapprovider-health", handler)])
        cln.plugin._write_locked = lambda payload: None  # unstarted plugin: no pipe
        _healthy_beats()
        from pyln.client.plugin import Request
        req = Request(cln.plugin, "test-id", "swapprovider-health", {})
        assert "swapprovider-health" in cln.plugin.methods  # registered
        cln.plugin._dispatch_request(req)  # the real dispatch path
        assert req.state.name == "FINISHED"
        assert req.result["verdict"] == "ok"
        json.dumps(req.result)  # wire-ready


class TestSwapStateCounts:
    def test_grace_held_inflight_and_expiring_counts(self):
        import time as _t
        sm = _sm()
        held = SwapData(is_reverse=True, locktime=5000, onchain_amount=1,
                        lightning_amount=1, redeem_script=b"\x51",
                        preimage=None, prepay_hash=None, privkey=b"\x01" * 32,
                        lockup_address="tb1qheld", receive_address="",
                        funding_txid="ab" * 32, spending_txid=None,
                        is_redeemed=False)
        held._payment_hash = "dd" * 32
        sm.swaps[held._payment_hash] = held
        sm._grace_hold_logged = {held._payment_hash}
        sm.invoices_to_pay = {"inflight-key": PAYMENT_INFLIGHT_LOCK,
                              "queued-key": _t.time() + 60}

        soon = SimpleNamespace(funding_status=InvoiceState.UNFUNDED,
                               created_at=_t.time(), expiry=60)
        far = SimpleNamespace(funding_status=InvoiceState.FUNDED,
                              created_at=_t.time(), expiry=3600)
        lnworker = SimpleNamespace(
            _hold_invoices={"soon": soon, "far": far})

        report = build_report(_provider(sm=sm, lnworker=lnworker))
        assert report["grace_held_swaps"] == 1
        assert report["inflight_payments"] == 1  # the lock sentinel only
        assert report["expiring_soon_invoices"] == 1  # unfunded + <5min left

    def test_late_commitment_releases_grace_hold(self):
        sm = _sm()
        key = "ee" * 32
        swap = SwapData(is_reverse=True, locktime=5000, onchain_amount=1,
                        lightning_amount=1, redeem_script=b"\x51",
                        preimage=None, prepay_hash=None, privkey=b"\x01" * 32,
                        lockup_address="tb1qlate", receive_address="",
                        funding_txid="cd" * 32, spending_txid=None,
                        is_redeemed=False)
        swap._payment_hash = key
        sm.swaps[key] = swap
        sm._grace_hold_logged = {key}
        sm.invoices_awaiting_funding.add(key)  # client registered late
        assert build_report(_provider(sm=sm))["grace_held_swaps"] == 0


# ---- shared consumer stub (real NostrTransport.check_direct_messages) ----

def _stub_transport(monkeypatch, send_boom=False):
    """NostrTransport built without __init__ (valcommon harness pattern);
    the relay yields two junk events (stale + replayed) and one real DM —
    the consumer beats on each wake, skips the junk, and serves (or
    fails to reply for, with send_boom) the real one. The aionostr
    PrivateKey patch is scoped by the caller's monkeypatch: 'decryption'
    of our plaintext events must stay the identity while
    check_direct_messages runs (after the function returns)."""
    import electrum_aionostr.key as aionostr_key
    from collections import defaultdict

    class _FakePrivKey:
        def __init__(self, raw):
            pass

        def decrypt_message(self, content, pubkey):
            return content

    monkeypatch.setattr(aionostr_key, "PrivateKey", _FakePrivKey)

    class _Ev:
        def __init__(self, ev_id, content, created_at, pubkey="ff" * 32):
            self.id = ev_id
            self.content = content
            self.created_at = created_at
            self.pubkey = pubkey

    events = [
        _Ev("old1", "{}", created_at=int(time.time()) - 10**6),  # stale
        _Ev("dup1", "{}", created_at=int(time.time())),
        _Ev("real1", json.dumps(
            {"method": "createswap", "pairId": "BTC/BTC",
             "type": "reversesubmarine", "invoiceAmount": 1,
             "preimageHash": "00" * 32, "claimPublicKey": "02" + "ab" * 32}),
            created_at=int(time.time())),
    ]

    class _Mgr:
        def get_events(self, query, single_event=False, only_stored=False):
            async def gen():
                for e in events:
                    yield e
            return gen()

    t = object.__new__(ss.NostrTransport)
    t.logger = MagicMock()
    t.sm = _sm()
    # r8: handle_request attributes against the transport config
    # (production __init__ always sets it; npub registry empty here)
    t.config = SimpleNamespace(test_npubs=())
    t.sm.is_server = True
    t.sm.is_initialized.set()
    t.sm.server_create_swap = AsyncMock(
        return_value={"id": "00" * 32, "invoice": "lnbcrt1"})
    t.private_key = b"\x01" * 32
    t.nostr_pubkey = "aa" * 32
    t.dm_replies = defaultdict(asyncio.Future)
    t.processed_event_ids = {}
    t.relay_manager = _Mgr()
    t.dead = asyncio.Event()
    sent = []

    async def fake_send(pubkey, content):
        if send_boom:
            raise RuntimeError("relay vanished before the reply")
        sent.append(content)
        return "reply"

    t.send_direct_message = fake_send
    return t, sent
