"""Regression: the bitcoind RPC client must self-heal, not dead-loop.

Live incident (playground #60, 2026-08-29): after a transient network
blip, the bitcoinrpc client's persistent httpx pool kept reusing dead
keepalive connections — every get_local_height() timed out with an
EMPTY exception string ("Could not get blockcount: ") every 10s for
15+ minutes while bitcoind itself was healthy (curl from inside the
container: 200 in 0.08s). Esplora lookups (fresh aiohttp session per
call) kept working. Only a container restart cleared it — the claims
machinery (R3) sat blocked the whole time.

Pinned policy: 3 consecutive failures rebuild the BitcoinRPC client
(fresh pool); any success resets the streak.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

_SWAP_DIR = Path(__file__).resolve().parent.parent / "swap-provider"
if str(_SWAP_DIR) not in sys.path:
    sys.path.insert(0, str(_SWAP_DIR))

# bitcoinrpc dep is node-bound (CLN RPC credentials) — sibling tests
# stub sys.modules the same way (test_esplora_lookup, test_plugin_config_pow)
class _FakeBitcoinRPC:
    last_url = None

    @classmethod
    def from_config(cls, url, auth):
        inst = cls()
        inst.url = url
        inst.auth = auth
        cls.last_url = url
        return inst


_stub_rpc = types.ModuleType("bitcoinrpc")
_stub_rpc.BitcoinRPC = _FakeBitcoinRPC
_stub_rpc.RPCError = Exception
sys.modules.setdefault("bitcoinrpc", _stub_rpc)

import plugin.bitcoin_core_rpc as bcr  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinRPCCredentials  # noqa: E402

PLUGIN_DIR = _SWAP_DIR / "plugin"


@pytest.fixture(autouse=True)
def _real_shape_rpc_class(monkeypatch):
    # whichever sibling stub won sys.modules, our construction needs a
    # from_config-shaped BitcoinRPC — patch the name the module CALLS,
    # auto-reverted after each test (no pollution the other way)
    monkeypatch.setattr(bcr, "BitcoinRPC", _FakeBitcoinRPC)


class _FakeLogger:
    def warning(self, *a, **k):
        pass

    error = debug = info = warning


def _rpc():
    creds = BitcoinRPCCredentials(
        host="127.0.0.1", port=18443, user="u", password="p",
        network="regtest")
    return bcr.BitcoinCoreRPC(logger=_FakeLogger(), bcore_rpc_credentials=creds)


class _DeadIface:
    """getblockcount that always times out with an empty-str error,
    exactly the live signature (asyncio.TimeoutError has str() == '')."""

    async def getblockcount(self):
        raise asyncio.TimeoutError()


def test_three_failures_rebuild_the_client():
    rpc = _rpc()
    dead = _DeadIface()
    rpc.iface = dead
    assert rpc.note_rpc_failure(RuntimeError()) is False
    assert rpc.note_rpc_failure(RuntimeError()) is False
    assert rpc.iface is dead, "must not rebuild before the streak hits 3"
    assert rpc.note_rpc_failure(RuntimeError()) is True
    assert rpc.iface is not dead, "3rd consecutive failure must rebuild the pool"


def test_success_resets_the_streak():
    rpc = _rpc()
    dead = _DeadIface()
    rpc.iface = dead
    rpc.note_rpc_failure(RuntimeError())
    rpc.note_rpc_failure(RuntimeError())
    rpc.note_rpc_success()
    assert rpc.note_rpc_failure(RuntimeError()) is False
    assert rpc.iface is dead, "streak reset means no rebuild on the next single failure"


def test_rebuilt_client_is_wired_to_the_same_wallet_url():
    rpc = _rpc()
    dead = _DeadIface()
    rpc.iface = dead
    for _ in range(3):
        rpc.note_rpc_failure(RuntimeError())
    # the wallet-selection URL path must survive the rebuild
    assert "/wallet/cln-subswapplugin" in str(getattr(rpc.iface, "url", "") or "")


def test_monitoring_loop_wires_the_policy():
    code = (PLUGIN_DIR / "chain_monitor.py").read_text()
    stripped = "\n".join(l for l in code.splitlines()
                         if not l.lstrip().startswith("#"))
    assert "self.note_rpc_success()" in stripped
    assert "self.note_rpc_failure(" in stripped
