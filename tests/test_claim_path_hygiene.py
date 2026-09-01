"""Claim-path hygiene + HSM binding (security review 2026-08-31, lane C):

C1 — the claim-broadcast failure handler catches BitcoinCoreRPCError
     (what the ChainMonitor actually raises), not just
     TxBroadcastError (the funding-path type) — the old single-type
     catch left the R3 error handler dead code.

C2 — per-swap claim in-flight guard: three drivers (block/timer
     trigger, funding-gate pass, startup sweep) must not interleave
     inside one swap's claim (double build + broadcast race).

C3 — the fee oracle never blocks the event loop: on-loop calls serve
     stale-while-revalidate (cache hit immediate even past TTL, one
     background refresh, cold cache returns None to the caller's
     fail-open path).

C4 — HSM binding: derived claim keys are checked against the stored
     claim_pubkey at signing time (fail-closed on hsm_secret change),
     and a startup canary alarms loudly on any hsm_secret change.
"""
import asyncio
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_PARENT = Path(__file__).resolve().parent.parent / "swap-provider"
if str(PLUGIN_PARENT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_PARENT))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

from plugin import fee_oracle  # noqa: E402
from plugin.fee_oracle import fetch_fee_sat_vb, _refresh_cache  # noqa: E402
from plugin.submarine_swaps import SwapManager  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinCoreRPCError  # noqa: E402

PLUGIN_FILE = (Path(PLUGIN_PARENT) / "plugin" / "submarine_swaps.py").read_text()

from electrum_ecc import ECPrivkey  # noqa: E402


class _Log(SimpleNamespace):
    def __init__(self):
        super().__init__(lines=[])

    def _n(self, lvl, msg, *a):
        self.lines.append((lvl, str(msg)))

    def debug(self, m, *a):
        self._n('debug', m, *a)

    def info(self, m, *a):
        self._n('info', m, *a)

    def warning(self, m, *a):
        self._n('warn', m, *a)

    def error(self, m, *a):
        self._n('error', m, *a)


# ── C1: broadcast failure handler catches the real exception type ────

class TestBroadcastCatch:
    def test_claim_broadcast_catches_bitcoin_core_rpc_error(self):
        # source-contract pin: the lnwatcher (ChainMonitor) broadcast
        # raises BitcoinCoreRPCError; TxBroadcastError belongs to the
        # CLNChainWallet funding path. Both must be caught at the claim
        # site or the R3 handler is dead code.
        assert "except (TxBroadcastError, BitcoinCoreRPCError)" in PLUGIN_FILE

    def test_bitcoin_core_rpc_error_is_imported(self):
        assert "from .bitcoin_core_rpc import BitcoinCoreRPCError" in PLUGIN_FILE


# ── C2: per-swap in-flight guard ─────────────────────────────────────

# ── C3: oracle never blocks the loop ─────────────────────────────────

class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeAsyncClient:
    payload = {"halfHourFee": 7}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        return _FakeResp(type(self).payload)


class TestOracleLoopSafety:
    def setup_method(self):
        fee_oracle._cache.clear()
        fee_oracle._last_refresh_attempt.clear()

    def test_offloop_blocking_fetch_unchanged(self, monkeypatch):
        called = []

        def fake_get(url, timeout=None):
            called.append(url)
            return _FakeResp({"halfHourFee": 3})

        monkeypatch.setattr(fee_oracle.httpx, "get", fake_get, raising=True)
        out = fetch_fee_sat_vb("https://oracle.test/api")
        assert out == 3.0 and called, "off-loop callers keep the sync fetch"

    async def test_onloop_cold_cache_returns_none_and_refreshes(self, monkeypatch):
        monkeypatch.setattr(fee_oracle.httpx, "AsyncClient", _FakeAsyncClient)
        out = fetch_fee_sat_vb("https://oracle.test/api")
        assert out is None, "cold on-loop call must fail open, not block"
        # let the spawned refresh task run
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert fee_oracle._cache["https://oracle.test/api"][1] == 7.0, \
            "background refresh must populate the cache"

    async def test_onloop_stale_entry_served_immediately(self):
        stale_time = time.monotonic() - 10 * fee_oracle._CACHE_TTL_SEC
        fee_oracle._cache["https://oracle.test/api"] = (stale_time, 9.0)
        t0 = time.monotonic()
        out = fetch_fee_sat_vb("https://oracle.test/api")
        assert out == 9.0, "stale value must be served while refreshing"
        assert time.monotonic() - t0 < 0.05, "must not block the loop"

    async def test_refresh_backoff_prevents_task_spam(self):
        stale_time = time.monotonic() - 10 * fee_oracle._CACHE_TTL_SEC
        fee_oracle._cache["https://oracle.test/api"] = (stale_time, 9.0)
        spawned = []

        class _Loop:
            def create_task(self, coro):
                spawned.append(coro)
                coro.close()
                return SimpleNamespace(done=lambda: True)

        # simulate being on a loop by monkeypatching get_running_loop
        orig = fee_oracle.asyncio.get_running_loop
        fee_oracle.asyncio.get_running_loop = lambda: _Loop()
        try:
            fetch_fee_sat_vb("https://oracle.test/api")
            fetch_fee_sat_vb("https://oracle.test/api")
            fetch_fee_sat_vb("https://oracle.test/api")
        finally:
            fee_oracle.asyncio.get_running_loop = orig
        assert len(spawned) == 1, "backoff must collapse concurrent spawns"


# ── C4: HSM binding (claim-path check + startup canary) ──────────────

GOOD_KEY = bytes.fromhex('11' * 32)
OTHER_KEY = bytes.fromhex('22' * 32)


def _pub(key: bytes) -> str:
    return ECPrivkey(key).get_public_key_bytes(compressed=True).hex()


class TestClaimKeyBinding:
    def _manager(self, derived):
        sm = object.__new__(SwapManager)
        sm._hsm_deriver = lambda label: derived
        return sm

    @staticmethod
    def _swap(claim_pubkey):
        return SimpleNamespace(privkey=None, claim_pubkey=claim_pubkey,
                               payment_hash=bytes(32))

    def test_matching_derivation_passes(self):
        sm = self._manager(GOOD_KEY)
        assert sm._get_swap_privkey(self._swap(_pub(GOOD_KEY))) == GOOD_KEY

    def test_mismatched_hsm_fails_closed(self):
        # hsm_secret changed (or scheme drifted): the derived key no
        # longer matches the pubkey baked into the redeem script —
        # REFUSE (no invalid-witness broadcast loop)
        sm = self._manager(OTHER_KEY)
        with pytest.raises(RuntimeError, match="derivation mismatch"):
            sm._get_swap_privkey(self._swap(_pub(GOOD_KEY)))

    def test_stored_old_format_key_skips_the_check(self):
        sm = self._manager(OTHER_KEY)
        swap = SimpleNamespace(privkey=GOOD_KEY.hex(), claim_pubkey=None,
                               payment_hash=bytes(32))
        assert sm._get_swap_privkey(swap) == GOOD_KEY


class TestHsmCanary:
    def _manager(self, derive_map):
        from plugin.submarine_swaps import sha256
        sm = object.__new__(SwapManager)
        sm._hsm_deriver = lambda label: derive_map[label]
        sm.logger = _Log()
        store = {}

        class _Db(SimpleNamespace):
            def get(self, k, d=None):
                return store.get(k, d)

            def put(self, k, v):
                store[k] = v

        sm.db = _Db()
        return sm, store, sha256

    def test_first_run_binds(self):
        from plugin.submarine_swaps import sha256
        sm, store, _ = self._manager({"swap-canary": b"k1"})
        assert sm.verify_hsm_canary() is True
        assert store["hsm_canary_sha"] == sha256(b"k1").hex()

    def test_same_hsm_ok_changed_hsm_alarms(self):
        from plugin.submarine_swaps import sha256
        sm, _, _ = self._manager({"swap-canary": b"k1"})
        sm.verify_hsm_canary()
        # node rebuilt: same label, different hsm_secret → different digest
        sm._hsm_deriver = lambda label: b"k2"
        assert sm.verify_hsm_canary() is False
        errs = [m for lvl, m in sm.logger.lines if lvl == 'error']
        assert any('HSM CANARY MISMATCH' in m for m in errs), \
            "the alarm must be loud"
