import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

# The bitcoinrpc fork dep is node-bound (CLN RPC credentials); config/PoW
# tests stub it — the module itself stays importable without it.
_stub_rpc = types.ModuleType("bitcoinrpc")
_stub_rpc.BitcoinRPC = object
_stub_rpc.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub_rpc)

from plugin import offer  # noqa: E402
from plugin.plugin_config import PluginConfig  # noqa: E402


class _Log:
    def warning(self, *a, **k): pass
    def info(self, *a, **k): pass
    def debug(self, *a, **k): pass
    def change_level(self, *a, **k): pass


class _Keypair:
    def __init__(self):
        import secrets
        self.privkey = secrets.token_bytes(32)
        # x-only pubkey = sha256(privkey) stand-in shaped right for tests
        import hashlib
        self.pubkey = hashlib.sha256(self.privkey).digest() + b"\x02" + bytes(32)


def _env(monkeypatch, relays="wss://test.relay"):
    monkeypatch.setenv("NOSTR_RELAYS", relays)


def test_pinned_nonce_below_target_fails_loud(monkeypatch):
    pubk = "ab" * 32
    good = offer.mine_ann_pow_nonce(pubk, 8)
    _env(monkeypatch)
    monkeypatch.setenv("ANN_POW_TARGET_BITS", "12")
    monkeypatch.setenv("ANN_POW_NONCE", hex(good))  # 8 bits < 12 target
    from plugin import plugin_config as pc
    monkeypatch.setattr(pc, "load_dotenv", lambda: None)
    monkeypatch.setattr(pc.Keypair, "from_private_key", classmethod(
        lambda cls, k: type("K", (), {"privkey": k,
                                      "pubkey": bytes.fromhex("02" + pubk)})()))
    with pytest.raises(Exception, match="reaches only"):
        pc.PluginConfig.from_cln_and_env(cln_plugin_handler=_StubCLN(pubk), logger=_Log())


class _StubCLN:
    """Real contract: fetch_cln_configuration() returns listconfigs()
    ['configs'] — a dict of {name: {'value_str': ...}} entries."""
    def __init__(self, pubk):
        self._pubk = pubk
    def derive_secret(self, label):
        return b"\x01" * 32
    def fetch_cln_configuration(self):
        return {
            "network": {"value_str": "regtest"},
            "bitcoin-rpcconnect": {"value_str": "bitcoind"},
            "bitcoin-rpcport": {"value_int": 18443},
            "bitcoin-rpcuser": {"value_str": "user"},
            "bitcoin-rpcpassword": {"value_str": "pass"},
            "bind-addr": {"value_str": "127.0.0.1:9735"},
        }


def test_low_target_mines_in_process(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ANN_POW_TARGET_BITS", "8")
    monkeypatch.delenv("ANN_POW_NONCE", raising=False)
    from plugin import plugin_config as pc
    monkeypatch.setattr(pc, "load_dotenv", lambda: None)
    monkeypatch.setattr(pc.Keypair, "from_private_key", classmethod(
        lambda cls, k: type("K", (), {"privkey": k, "pubkey": bytes.fromhex("02" + "ab" * 32)})()))
    cfg = pc.PluginConfig.from_cln_and_env(cln_plugin_handler=_StubCLN("ab" * 32), logger=_Log())
    assert cfg.ann_pow_nonce > 0
    assert offer.nostr_ann_pow_bits("ab" * 32, cfg.ann_pow_nonce) >= 8
