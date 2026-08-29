import asyncio
import sys
import time
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

import plugin.bitcoin_core_rpc as bcr  # noqa: E402
from plugin.bitcoin_core_rpc import (  # noqa: E402
    BitcoinCoreRPC, BitcoinCoreRPCError)


class _FakeEsplora:
    """Serves the two endpoints the esplora lookup mode uses — same shapes
    as mempool.space / the lab mempool-shim."""
    def __init__(self, tx_status=None, tx_hex=None):
        self.calls = []
        self.tx_status = tx_status or {}
        self.tx_hex = tx_hex

    async def route(self, path):
        self.calls.append(path)
        if path.startswith("/tx/") and path.endswith("/hex"):
            return self.tx_hex  # None = unknown tx
        if path.startswith("/tx/"):
            return self.tx_status or None
        raise AssertionError(f"unexpected esplora path {path}")


class _Mon(BitcoinCoreRPC):
    def __init__(self, fake):
        self.fake = fake  # skip RPC construction — lookup tests only
        self._logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None),
                                      "info": staticmethod(lambda *a, **k: None)})()

    async def _esplora_get(self, path):
        return await self.fake.route(path)


CONFIRMED = {
    "txid": "ab" * 32,
    "locktime": 318500,
    "status": {"confirmed": True, "block_height": 317815,
               "block_hash": "cd" * 32, "block_time": 1787000000},
}


async def test_esplora_get_tx_height_maps_confirmed():
    m = _Mon(_FakeEsplora(tx_status=CONFIRMED))
    m.set_lookup_mode("esplora", ["http://x"])
    info = await m.get_tx_height(CONFIRMED["txid"])
    assert info.height == 317815
    assert info.conf == 1
    assert info.timestamp == 1787000000
    assert info.header_hash == "cd" * 32
    assert info.wanted_height == 318500
    assert m.fake.calls == [f"/tx/{CONFIRMED['txid']}"]


async def test_esplora_get_tx_height_unconfirmed():
    m = _Mon(_FakeEsplora(tx_status={
        "txid": "ab" * 32, "locktime": 0, "status": {"confirmed": False}}))
    m.set_lookup_mode("esplora", ["http://x"])
    info = await m.get_tx_height("ab" * 32)
    assert info.height is None and info.conf == 0
    assert info.wanted_height is None  # locktime 0 → None, matches txindex path


async def test_esplora_get_tx_height_unknown_raises():
    m = _Mon(_FakeEsplora(tx_status=None))
    m.set_lookup_mode("esplora", ["http://x"])
    with pytest.raises(Exception, match="does not know"):
        await m.get_tx_height("ab" * 32)


async def test_esplora_get_transaction_hex_and_unknown():
    raw = "0200000000010100" + "00" * 30  # shape only; Transaction accepts raw str
    m = _Mon(_FakeEsplora(tx_hex=raw))
    m.set_lookup_mode("esplora", ["http://x"])
    assert await m.get_transaction("ab" * 32) is not None
    m.fake.tx_hex = None
    assert await m.get_transaction("ab" * 32) is None  # unknown → None, not raise


def test_lookup_mode_routing():
    m = _Mon(_FakeEsplora())
    m.set_lookup_mode("txindex")
    assert m._chain_lookup_mode == "txindex" and m._esplora_urls == []
    m.set_lookup_mode("esplora", ["http://shim:8788/"])
    assert m._esplora_urls == ["http://shim:8788"]  # trailing slash stripped


# ---------------------------------------------------------------------------
# #34: esplora fetch timeouts — the live wedge (2026-08-28/29) showed
# fetches hanging 30-40 MINUTES with a nominally-configured aiohttp
# total=20s that never fired, wedging the whole monitoring loop (no
# 'New blockheight' lines, network-wide claim stalls, burst on return).
# The fetch layer must: hard-cap EVERY attempt (a deadline no transport
# subtlety can defeat), retry an endpoint a bounded number of times,
# then fall through to the next ESPLORA_URLS entry.
# ---------------------------------------------------------------------------

DEAD = "http://127.0.0.1:1"    # refused fast on any box (no DNS in play)
LIVE = "http://127.0.0.2:1"    # distinct base for handler dispatch


class _FetchMon(BitcoinCoreRPC):
    """Minimal harness that exercises the REAL _esplora_get (no override)."""

    def __init__(self):
        self._logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None),
                                       "info": staticmethod(lambda *a, **k: None),
                                       "warning": staticmethod(lambda *a, **k: None),
                                       "error": staticmethod(lambda *a, **k: None)})()


def _wire_handler(monkeypatch, handler):
    monkeypatch.setattr(BitcoinCoreRPC, "_new_esplora_client",
                        lambda self: httpx.AsyncClient(
                            transport=httpx.MockTransport(handler)))


def _shrink_caps(monkeypatch, cap_s=0.2):
    monkeypatch.setattr(bcr, "ESPLORA_ATTEMPT_HARD_CAP_S", cap_s)


async def test_esplora_hanging_endpoint_hits_hard_cap_and_falls_through(monkeypatch):
    """THE #34 regression: a wedged endpoint (accepts, never answers) must
    cost one bounded attempt-cycle, then the next endpoint serves the lookup.
    The watcher must never block indefinitely on one endpoint."""
    calls = {"dead": 0, "live": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "127.0.0.2":
            calls["live"] += 1
            return httpx.Response(200, json={"txid": "ab" * 32, "status": {}})
        calls["dead"] += 1
        await asyncio.sleep(30)  # the wedge: headers never arrive
        return httpx.Response(200, json={})

    _wire_handler(monkeypatch, handler)
    _shrink_caps(monkeypatch)
    m = _FetchMon()
    m.set_lookup_mode("esplora", [DEAD, LIVE])

    t0 = time.monotonic()
    res = await m._esplora_get(f"/tx/{'ab' * 32}")
    elapsed = time.monotonic() - t0

    assert res is not None and res.get("txid") == "ab" * 32
    assert calls["dead"] == bcr.ESPLORA_ATTEMPTS_PER_ENDPOINT  # bounded retry, not forever
    assert calls["live"] == 1
    assert elapsed < 10, f"fallback took {elapsed:.1f}s — hard cap not bounding"


async def test_esplora_all_endpoints_dead_raises_bounded(monkeypatch):
    """Dead stack: bounded attempts, then the typed error — never a hang."""
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(30)
        return httpx.Response(200, json={})

    _wire_handler(monkeypatch, handler)
    _shrink_caps(monkeypatch)
    m = _FetchMon()
    m.set_lookup_mode("esplora", [DEAD])

    t0 = time.monotonic()
    with pytest.raises(BitcoinCoreRPCError, match="failed on all 1 endpoints"):
        await m._esplora_get("/tx/" + "ab" * 32)
    elapsed = time.monotonic() - t0
    assert calls["n"] == bcr.ESPLORA_ATTEMPTS_PER_ENDPOINT
    assert elapsed < 10, f"dead endpoint cost {elapsed:.1f}s — unbounded"


async def test_esplora_retries_endpoint_then_succeeds(monkeypatch):
    """Transient 5xx on attempt 1 must not fail the lookup (bounded retry),
    nor burn the fallback endpoint."""
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(502)  # mempool.space 5xx class
        return httpx.Response(200, text="deadbeef",
                              headers={"Content-Type": "text/plain"})

    _wire_handler(monkeypatch, handler)
    m = _FetchMon()
    m.set_lookup_mode("esplora", [DEAD])

    res = await m._esplora_get("/tx/" + "ab" * 32 + "/hex")
    assert res == "deadbeef"
    assert calls["n"] == 2


async def test_esplora_404_is_definitive_no_retry(monkeypatch):
    """404 = esplora's 'unknown txid' answer — a definitive response, not
    an endpoint failure: no retry, no fallback, None returned."""
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    _wire_handler(monkeypatch, handler)
    m = _FetchMon()
    m.set_lookup_mode("esplora", [DEAD, LIVE])

    assert await m._esplora_get("/tx/" + "cd" * 32) is None
    assert calls["n"] == 1


async def test_esplora_client_timeout_config_is_bounded():
    """The per-attempt httpx timeout must be explicit — the default (5 min)
    or None would put the bound entirely on the hard cap."""
    mon = _FetchMon()
    client = mon._new_esplora_client()
    try:
        t = client.timeout
        assert t is not None and t.connect is not None and t.read is not None
        assert t.connect <= 10 and t.read <= 30, (
            f"per-attempt timeout too generous: connect={t.connect} read={t.read}")
    finally:
        await client.aclose()


async def test_esplora_no_endpoints_raises_typed(monkeypatch):
    m = _FetchMon()
    m.set_lookup_mode("esplora", [])
    with pytest.raises(BitcoinCoreRPCError, match="failed on all 0 endpoints"):
        await m._esplora_get("/tx/" + "ab" * 32)


async def test_esplora_endpoint_exhaustion_logs_warning(monkeypatch):
    """#23 severity lesson: money-path degradation must be separable by
    level — an exhausted endpoint logs a WARNING naming it."""
    warned = []

    class L:
        debug = staticmethod(lambda *a, **k: None)
        info = staticmethod(lambda *a, **k: None)
        error = staticmethod(lambda *a, **k: None)

        def warning(self, *a, **k):
            warned.append(" ".join(str(x) for x in a))

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        return httpx.Response(200, json={})

    _wire_handler(monkeypatch, handler)
    _shrink_caps(monkeypatch)
    m = _FetchMon()
    m._logger = L()
    m.set_lookup_mode("esplora", [DEAD, LIVE])

    with pytest.raises(BitcoinCoreRPCError):
        await m._esplora_get("/tx/" + "ab" * 32)
    assert any(DEAD in w for w in warned), f"no warning named the dead endpoint: {warned}"


def test_create_transaction_retries_when_excess_below_dust(monkeypatch):
    # live-earned 2026-08-23 (mutinynet GUI e2e): CLN's minimal coin
    # selection returns excess_msat=0 despite a +1000 ask slack — excess
    # depends on UTXO granularity, not the ask. A zero-value change
    # output kills the funding tx ("tx needs to have at least 1 output").
    # create_transaction must escalate the ask until excess >= dust.
    calls = []

    class FakeRPC:
        def listfunds(self):
            # healthy pool: one free plain-script output (issue #29 filter
            # only offers plain P2WPKH/P2TR confirmed+unreserved outputs)
            return {"outputs": [{
                "txid": "ab" * 32, "output": 0, "amount_msat": 100_000_000,
                "status": "confirmed", "reserved": False,
                "scriptpubkey": "0014" + "11" * 20}]}
        def utxopsbt(self, **kw):
            calls.append(kw["satoshi"])
            # first two attempts: excess below dust; third: healthy
            excess = 0 if len(calls) < 3 else 700_000
            return {"psbt": "cHNidP8BAgQCAAAAAQ==", "excess_msat": excess}
        def signpsbt(self, psbt):
            return {"signed_psbt": psbt}

    class FakePartial:
        def __init__(self): self.outputs = []
        @classmethod
        def from_raw_psbt(cls, raw): return cls()
        def add_outputs(self, outs): self.outputs += list(outs)
        def set_rbf(self, b): pass
        def _serialize_as_base64(self): return "cHNidP8BAgQCAAAAAQ=="
        def finalize_psbt(self): pass

    import plugin.cln_chain as cc
    monkeypatch.setattr(cc, "PartialTransaction", FakePartial, raising=False)
    holder = cc.CLNChainWallet
    inst = object.__new__(holder)
    inst.rpc = FakeRPC()
    inst.logger = type("L", (), {"error": staticmethod(lambda *a, **k: None),
                                 "info": staticmethod(lambda *a, **k: None)})()
    class Cfg: cln_feerate_str = "urgent"
    inst.config = Cfg()

    out = type("O", (), {"value": 18995, "scriptpubkey": b"\x00" * 34})()
    tx = inst.create_transaction(outputs_without_change=[out], rbf=True)
    assert tx is not None, "should succeed after escalation"
    assert len(calls) == 3, f"expected 3 escalating asks (0,0,700sat), got {len(calls)}"
    assert calls[1] > calls[0] and calls[2] > calls[1], "asks must escalate"
