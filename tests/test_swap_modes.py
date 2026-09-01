"""SWAP_MODES feature flags (owner ask 2026-08-21; design in
docs/issue-38-d2-prepayment-design.md "Feature-flag system"): enable or
disable swap directions at the operator level. Disabled modes are
refused at the RPC boundary with a typed error AND de-advertised in
the nostr offer (caps zeroed for that direction) so routing never
sends clients to a provider that would refuse them.

Canonical vocabulary (AGENTS.md): ln_to_onchain = client pays LN hold,
receives onchain (wire 'createswap'/reversesubmarine; electrum's
create_normal_swap SERVER-side). onchain_to_ln = client funds onchain,
receives LN (wire 'createnormalswap'+'addswapinvoice'; electrum's
create_reverse_swap SERVER-side — the naming flip is electrum's
PoV quirk, do NOT re-derive it).

Run: python3 -m pytest tests/test_swap_modes.py -v
"""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

import types as _types
sys.modules.setdefault("bitcoinrpc",
                       _types.SimpleNamespace(BitcoinRPC=object, RPCError=RuntimeError))

from plugin.plugin_config import parse_swap_modes, SWAP_MODE_NAMES  # noqa: E402
from plugin.submarine_swaps import SwapManager  # noqa: E402


class TestParseSwapModes:
    def test_default_all_enabled(self, monkeypatch):
        monkeypatch.delenv("SWAP_MODES", raising=False)
        assert parse_swap_modes(None) == {"ln_to_onchain": True, "onchain_to_ln": True}

    def test_csv_disables_one(self):
        assert parse_swap_modes("onchain_to_ln") == \
            {"ln_to_onchain": False, "onchain_to_ln": True}

    def test_json_object(self):
        assert parse_swap_modes('{"ln_to_onchain": true, "onchain_to_ln": false}') == \
            {"ln_to_onchain": True, "onchain_to_ln": False}

    def test_json_array(self):
        assert parse_swap_modes('["onchain_to_ln"]') == \
            {"ln_to_onchain": False, "onchain_to_ln": True}

    def test_unknown_mode_fails_loud(self):
        with pytest.raises(Exception, match="unknown swap mode"):
            parse_swap_modes("ln_to_onchain,warp_drive")

    def test_names_are_the_canonical_two(self):
        assert SWAP_MODE_NAMES == ("ln_to_onchain", "onchain_to_ln")


def _gated_manager(modes):
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.config = SimpleNamespace(swap_modes=modes)
    return sm


class TestRpcBoundaryGate:
    def test_disabled_ln_to_onchain_refused_at_createswap(self):
        sm = _gated_manager({"ln_to_onchain": False, "onchain_to_ln": True})
        r = sm._require_swap_mode("ln_to_onchain")
        assert r is not None and "disabled" in r["error"] and "ln_to_onchain" in r["error"]

    def test_enabled_mode_passes(self):
        sm = _gated_manager({"ln_to_onchain": True, "onchain_to_ln": True})
        assert sm._require_swap_mode("ln_to_onchain") is None

    def test_the_gate_is_first_in_server_create_swap(self):
        # source contract: the mode gate sits BEFORE the datastore
        # breaker and every capacity probe — a disabled mode must cost
        # zero side effects (no probes, no freshness reads)
        src = (_plugin / "submarine_swaps.py").read_text()
        fn = src.split("async def server_create_swap")[1].split("\n    async def")[0]
        gate_idx = fn.index("_require_swap_mode")
        breaker_idx = fn.index("_datastore_healthy")
        assert gate_idx < breaker_idx, "mode gate must precede the breaker"

    def test_the_gate_covers_all_three_handlers(self):
        src = (_plugin / "submarine_swaps.py").read_text()
        # addswapinvoice's handler is SYNC (def, not async def)
        for handler in ("async def server_create_swap(", "def server_add_swap_invoice("):
            fn = src.split(handler)[1].split("\n    async def")[0].split("\n    def ")[0]
            assert "_require_swap_mode" in fn, f"{handler} must gate its mode"
        # createnormalswap's handler too
        fn = src.split("async def server_create_normal_swap")[1].split("\n    async def")[0]
        assert "_require_swap_mode" in fn


class TestOfferAdvertisement:
    def test_disabled_direction_zeroes_its_cap(self):
        from plugin.offer import build_offer_content
        content = json.loads(build_offer_content(
            percentage_fee=0.5, mining_fee_sat=138, min_amount_sat=20_000,
            max_forward_sat=450_000, max_reverse_sat=234_514,
            relays_csv="ws://relay", pow_nonce=0x554f,
            swap_modes={"ln_to_onchain": False, "onchain_to_ln": True}))
        assert content["max_reverse_amount"] == 0, "disabled ln_to_onchain must zero maxReverse"
        assert content["max_forward_amount"] == 450_000

    def test_enabled_modes_keep_offer_byte_shape_no_new_key(self):
        # a fully-enabled config must not change the offer content at
        # all (byte-compat with stock 4.8.1 parsing)
        from plugin.offer import build_offer_content
        plain = build_offer_content(
            percentage_fee=0.5, mining_fee_sat=138, min_amount_sat=20_000,
            max_forward_sat=450_000, max_reverse_sat=234_514,
            relays_csv="ws://relay", pow_nonce=0x554f)
        flagged = build_offer_content(
            percentage_fee=0.5, mining_fee_sat=138, min_amount_sat=20_000,
            max_forward_sat=450_000, max_reverse_sat=234_514,
            relays_csv="ws://relay", pow_nonce=0x554f,
            swap_modes={"ln_to_onchain": True, "onchain_to_ln": True})
        assert plain == flagged


import json  # noqa: E402  (used by TestOfferAdvertisement)
