import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

from plugin.bitcoin_core_rpc import BitcoinCoreRPC  # noqa: E402


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
