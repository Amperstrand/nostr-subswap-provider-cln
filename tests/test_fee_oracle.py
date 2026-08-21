"""O4 feerate-oracle tests (AGENTS.md future-optimizations; live-observed
2026-08-21: 'fallback fee rate of 60 sat/vB because cln rpc returned []'
priced a 222-vB claim at 4400 sats when signet blocks paid 0-6 sat/vB).

Order: CLN feerates RPC -> mempool-style oracle (cached, clamped,
short-timeout) -> FALLBACK_FEE_SATVB.

Run: python3 -m pytest tests/test_fee_oracle.py -v
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin import fee_oracle  # noqa: E402


class _Oracle(BaseHTTPRequestHandler):
    payload = {"halfHourFee": 2.5}
    delay = 0.0
    status = 200

    def do_GET(self):
        if _Oracle.delay:
            time.sleep(_Oracle.delay)
        body = json.dumps(_Oracle.payload).encode()
        self.send_response(_Oracle.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def oracle_url():
    srv = HTTPServer(("127.0.0.1", 0), _Oracle)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/api"
    srv.shutdown()


def _reset_cache(monkeypatch=None):
    fee_oracle._cache.clear()


def test_oracle_used_when_cln_estimate_missing(oracle_url):
    _reset_cache()
    got = fee_oracle.fetch_fee_sat_vb(oracle_url, timeout=2)
    assert got == pytest.approx(2.5)


def test_oracle_cached_between_calls(oracle_url):
    _reset_cache()
    first = fee_oracle.fetch_fee_sat_vb(oracle_url, timeout=2)
    # kill the payload — second call must still succeed from cache
    _Oracle.payload = {"halfHourFee": 999}
    second = fee_oracle.fetch_fee_sat_vb(oracle_url, timeout=2)
    assert second == first


def test_oracle_down_returns_none(oracle_url):
    _reset_cache()
    assert fee_oracle.fetch_fee_sat_vb(
        "http://127.0.0.1:1/api", timeout=1) is None


def test_oracle_slow_returns_none(oracle_url):
    _reset_cache()
    _Oracle.delay = 3.0
    try:
        assert fee_oracle.fetch_fee_sat_vb(oracle_url, timeout=0.5) is None
    finally:
        _Oracle.delay = 0.0


def test_oracle_clamps_out_of_range(oracle_url):
    _reset_cache()
    _Oracle.payload = {"halfHourFee": 100000}
    try:
        # out-of-range oracle value = broken oracle -> None (fail-open,
        # caller falls back), never an insane feerate
        assert fee_oracle.fetch_fee_sat_vb(oracle_url, timeout=2) is None
    finally:
        _Oracle.payload = {"halfHourFee": 2.5}


def test_default_url_per_network():
    from plugin.constants import BitcoinSignet, BitcoinMainnet, BitcoinMutinynet
    assert "mempool.space/signet" in fee_oracle.default_oracle_url(BitcoinSignet)
    assert "mutinynet.com" in fee_oracle.default_oracle_url(BitcoinMutinynet)
    assert fee_oracle.default_oracle_url(BitcoinMainnet).startswith("https://mempool.space/api")


class TestGetChainFeeChain:
    """CLNChainWallet.get_chain_fee must try oracle between CLN and the
    static fallback."""

    def _wallet(self, feerates_result=None, feerates_raises=False,
                oracle_val=None):
        from plugin.cln_chain import CLNChainWallet
        w = CLNChainWallet.__new__(CLNChainWallet)
        w.logger = SimpleNamespace(
            debug=lambda *a, **k: None, info=lambda *a, **k: None,
            warning=lambda *a, **k: None, error=lambda *a, **k: None)
        w.rpc = MagicMock()
        if feerates_raises:
            w.rpc.feerates.side_effect = TimeoutError("cln down")
        else:
            w.rpc.feerates.return_value = feerates_result or \
                {"perkb": {"estimates": []}}
        w.config = SimpleNamespace(
            confirmation_speed_target_blocks=10,
            fallback_fee_sat_per_vb=60,
            fee_oracle_url=oracle_val)
        return w

    def test_cln_empty_oracle_used(self, oracle_url, monkeypatch):
        _reset_cache()
        w = self._wallet(oracle_val=oracle_url)
        # 222-vB claim at oracle 2.5 sat/vB = 555 sats, NOT 60*222=13320
        assert w.get_chain_fee(size_vbyte=222) == pytest.approx(555, rel=1)

    def test_cln_empty_oracle_down_falls_back(self):
        _reset_cache()
        w = self._wallet(oracle_val="http://127.0.0.1:1/api")
        assert w.get_chain_fee(size_vbyte=222) == 60 * 222

    def test_cln_estimate_wins_over_oracle(self, oracle_url):
        _reset_cache()
        w = self._wallet(
            feerates_result={"perkb": {"estimates": [
                {"blockcount": 10, "smoothed_feerate": 4000}]}},
            oracle_val=oracle_url)
        # cln says 4 sat/vB — oracle (2.5) must NOT be consulted
        assert w.get_chain_fee(size_vbyte=100) == 400

    def test_no_oracle_configured_falls_back(self):
        _reset_cache()
        w = self._wallet(oracle_val=None)
        assert w.get_chain_fee(size_vbyte=100) == 60 * 100
