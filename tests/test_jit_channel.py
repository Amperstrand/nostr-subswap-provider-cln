"""JIT channel opener tests (LSP model) — validates feature gating,
trigger conditions, liquidity-aware channel sizing, and integration."""
from __future__ import annotations

import os
import pathlib
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin.jit_channel import (
    JIT_FEE_BUFFER_SAT,
    JIT_MIN_CHANNEL_SAT,
    decode_payee_node,
    has_channel_to,
    is_no_route_failure,
    jit_channel_size,
    jit_enabled,
    jit_liquidity_factor,
    open_jit_channel,
    sufficient_onchain,
    wait_channel_lockin,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Reset the env var before each test for isolation."""
    monkeypatch.delenv("SWAPSERVER_JIT_CHANNEL", raising=False)


class TestFeatureGating:
    def test_disabled_by_default(self):
        assert not jit_enabled()

    def test_env_pct_20(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "20")
        assert jit_enabled()
        assert jit_liquidity_factor() == pytest.approx(0.20)

    def test_env_pct_35(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "35")
        assert jit_enabled()
        assert jit_liquidity_factor() == pytest.approx(0.35)

    def test_env_pct_50(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "50")
        assert jit_enabled()
        assert jit_liquidity_factor() == pytest.approx(0.50)

    def test_env_decimal_pct(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "12.5")
        assert jit_enabled()
        assert jit_liquidity_factor() == pytest.approx(0.125)

    def test_env_invalid_falls_to_disabled(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "yes")
        assert not jit_enabled()

    def test_env_zero(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "0")
        assert not jit_enabled()

    def test_env_negative_treated_as_disabled(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "-5")
        assert not jit_enabled()

    def test_rpc_option_checked(self):
        rpc = MagicMock()
        rpc.listconfigs.return_value = {
            "#swapserver.jit_channel#": {"value_str": "25"}
        }
        assert jit_enabled(rpc)
        assert jit_liquidity_factor(rpc) == pytest.approx(0.25)

    def test_env_overrides_rpc_when_higher(self, monkeypatch):
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "40")
        rpc = MagicMock()
        rpc.listconfigs.return_value = {
            "#swapserver.jit_channel#": {"value_str": "10"}
        }
        assert jit_enabled(rpc)
        assert jit_liquidity_factor(rpc) == pytest.approx(0.40)

    def test_pct_100_means_double(self, monkeypatch):
        """100% extra = channel twice the invoice."""
        monkeypatch.setenv("SWAPSERVER_JIT_CHANNEL", "100")
        size = jit_channel_size(100_000, liquidity_factor=jit_liquidity_factor())
        assert size >= 100_000 + JIT_FEE_BUFFER_SAT + 100_000


class TestNoRouteDetection:
    def test_cln_205_message(self):
        assert is_no_route_failure(
            {"code": 205, "message": "There is no connection between source and destination at all"})

    def test_cln_205_unknown_destination_node(self):
        # LIVE-captured 2026-08-21 regtest JIT live-fire: xpay emits this
        # variant when the payee is absent from the gossip map entirely
        # (zero-channel fresh node). The original signature list missed
        # it and JIT silently never fired.
        assert is_no_route_failure(
            {"code": 205, "message": "Failed: Unknown destination node "
             "0321a1cf8ee76f3fa182a3190e852b7030dbd363a0f59578c6f4a0f63528bf9dcc"})

    def test_cln_205_unknown_destination_full_rpc_log_string(self):
        # the exact string the plugin's pay_invoice returns as `log` on
        # the RPC-failure path (live-captured, jit live-fire session)
        assert is_no_route_failure(
            "pay_invoice call to CLN failed: RPC call failed: method: pay, "
            "payload: {'bolt11': 'lnbcrt250u1...', 'retry_for': 225}, "
            "error: {'code': 205, 'message': 'Failed: Unknown destination "
            "node 0321a1cf8ee76f3fa182a3190e852b7030dbd363a0f59578c6f4a0f63528bf9dcc'}")


    def test_raw_string_variant(self):
        assert is_no_route_failure("Failed: We could not find a usable set of paths")

    def test_temporary_failure_is_not_no_route(self):
        assert not is_no_route_failure(
            {"code": 209, "message": "Timed out: temporary_channel_failure for 123x4x5"})

    def test_incorrect_payment_details_is_not_no_route(self):
        assert not is_no_route_failure(
            {"code": 203, "message": "Destination said it doesn't know invoice"})

    def test_none(self):
        assert not is_no_route_failure(None)

    def test_empty(self):
        assert not is_no_route_failure("")

    def test_dict_with_log_field(self):
        assert is_no_route_failure(
            {"log": "no route found to destination", "status": "failed"})


class TestChannelSizingWithLiquidity:
    def test_minimum_applies_for_small_invoices(self):
        size = jit_channel_size(20_000, liquidity_factor=0.20)
        assert size == JIT_MIN_CHANNEL_SAT  # floored

    def test_liquidity_factor_adds_retained_capacity(self):
        """A 100k invoice at 20% liquidity should open ≥ 100k + 1k + 20k."""
        size = jit_channel_size(100_000, liquidity_factor=0.20)
        assert size >= 100_000 + JIT_FEE_BUFFER_SAT + 20_000

    def test_generous_factor_retains_more(self):
        # above the 200k floor — small invoices all floor to the same size
        conservative = jit_channel_size(400_000, liquidity_factor=0.20)
        generous = jit_channel_size(400_000, liquidity_factor=0.50)
        assert generous > conservative

    def test_capped_at_max_per_invoice(self):
        size = jit_channel_size(1_000_000, liquidity_factor=0.50)
        assert size <= 1_000_000 * 10 + JIT_FEE_BUFFER_SAT

    def test_retained_capacity_stays_our_side(self):
        """After routing the invoice through the new channel, the
        liquidity_factor portion remains spendable on our side."""
        invoice = 100_000
        factor = 0.20
        size = jit_channel_size(invoice, liquidity_factor=factor)
        retained = size - invoice - JIT_FEE_BUFFER_SAT
        assert retained >= invoice * factor - 1_000  # -1k tolerance


class TestSufficientOnchain:
    def test_enough_confirmed(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 100_000_000, "status": "confirmed"}]
        }
        assert sufficient_onchain(50_000, rpc)

    def test_reserved_outputs_excluded(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 100_000_000, "status": "confirmed", "reserved": True}]
        }
        assert not sufficient_onchain(50_000, rpc)

    def test_emergency_reserve_needed(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 60_000_000, "status": "confirmed"}]
        }
        assert not sufficient_onchain(50_000, rpc)

    def test_rpc_error_returns_false(self):
        rpc = MagicMock()
        rpc.listfunds.side_effect = Exception("rpc down")
        assert not sufficient_onchain(50_000, rpc)


class TestHasChannelTo:
    def test_existing_channel(self):
        rpc = MagicMock()
        rpc.listpeerchannels.return_value = {
            "channels": [{"peer_id": "abc123", "state": "CHANNELD_NORMAL"}]
        }
        assert has_channel_to("abc123", rpc)

    def test_no_channel(self):
        rpc = MagicMock()
        rpc.listpeerchannels.return_value = {"channels": []}
        assert not has_channel_to("abc123", rpc)

    def test_rpc_error(self):
        rpc = MagicMock()
        rpc.listpeers.side_effect = Exception("boom")
        assert not has_channel_to("abc123", rpc)

    def test_flat_listpeerchannels_shape(self):
        # CLN v26: channels are NOT under listpeers peers — a
        # pending-or-normal channel must be visible via
        # listpeerchannels (live-earned: the blind check double-opened
        # a second JIT channel while the first awaited lockin)
        rpc = MagicMock()
        rpc.listpeers.return_value = {"peers": [{"id": "abc123", "connected": True}]}
        rpc.listpeerchannels.return_value = {
            "channels": [
                {"peer_id": "other", "state": "CHANNELD_NORMAL"},
                {"peer_id": "abc123", "state": "CHANNELD_AWAITING_LOCKIN"},
            ]
        }
        assert has_channel_to("abc123", rpc)

    def test_flat_shape_no_channel(self):
        rpc = MagicMock()
        rpc.listpeers.return_value = {"peers": [{"id": "abc123", "connected": True}]}
        rpc.listpeerchannels.return_value = {
            "channels": [{"peer_id": "other", "state": "CHANNELD_NORMAL"}]
        }
        assert not has_channel_to("abc123", rpc)


class TestDecodePayee:
    def test_payee_field(self):
        rpc = MagicMock()
        rpc.decode.return_value = {"payee": "03abc123"}
        assert decode_payee_node("lnbc123", rpc) == "03abc123"

    def test_destination_field(self):
        rpc = MagicMock()
        rpc.decode.return_value = {"destination": "03abc123"}
        assert decode_payee_node("lnbc123", rpc) == "03abc123"

    def test_decode_fails(self):
        rpc = MagicMock()
        rpc.decode.side_effect = Exception("bad invoice")
        assert decode_payee_node("garbage", rpc) is None


class TestOpenJitChannel:
    def test_calls_fundchannel_with_liquidity_sized_amount(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 500_000_000, "status": "confirmed"}]
        }
        rpc.fundchannel.return_value = {"txid": "abc123", "channel_id": "xyz"}
        result = open_jit_channel("03abc", 20_000, rpc, liquidity_factor=0.20)
        assert result is not None
        call_args = rpc.fundchannel.call_args
        assert "200000sat" in str(call_args)  # floored at JIT_MIN (electrum MIN_FUNDING_SAT)

    def test_insufficient_funds_returns_none(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {"outputs": []}
        assert open_jit_channel("03abc", 20_000, rpc) is None

    def test_fundchannel_error_returns_none(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 500_000_000, "status": "confirmed"}]
        }
        rpc.fundchannel.side_effect = Exception("already have channel")
        assert open_jit_channel("03abc", 20_000, rpc) is None


class TestWaitChannelLockin:
    def test_open_channel_returns_true(self):
        rpc = MagicMock()
        rpc.listpeerchannels.return_value = {
            "channels": [{
                "peer_id": "abc", "state": "CHANNELD_NORMAL",
                "short_channel_id": "123x4x5",
            }]
        }
        assert wait_channel_lockin("abc", rpc, timeout_s=1)

    def test_no_channel_times_out(self):
        rpc = MagicMock()
        rpc.listpeerchannels.return_value = {"channels": []}
        assert not wait_channel_lockin("abc", rpc, timeout_s=1)

    def test_flat_listpeerchannels_shape(self):
        # CLN v26 removed the per-peer channel nesting: listpeers carries
        # NO channels key, channels live in listpeerchannels only
        # (live-earned: a nested-only read polled blind for 600s while
        # the channel was already NORMAL).
        rpc = MagicMock()
        rpc.listpeers.return_value = {"peers": [{"id": "abc", "connected": True}]}
        rpc.listpeerchannels.return_value = {
            "channels": [
                {"peer_id": "abc", "state": "CHANNELD_AWAITING_LOCKIN"},
                {"peer_id": "abc", "state": "CHANNELD_NORMAL", "short_channel_id": "700x1x0"},
            ]
        }
        assert wait_channel_lockin("abc", rpc, timeout_s=1)

    def test_flat_shape_other_peer_channels_ignored(self):
        rpc = MagicMock()
        rpc.listpeers.return_value = {"peers": [{"id": "abc", "connected": True}]}
        rpc.listpeerchannels.return_value = {
            "channels": [{"peer_id": "other", "state": "CHANNELD_NORMAL"}]
        }
        assert not wait_channel_lockin("abc", rpc, timeout_s=1)


class TestRetryLoopIntegration:
    """Verifies the JIT block is present and gated in the retry loop."""

    def test_jit_imported(self):
        src = (pathlib.Path(__file__).parent.parent / "swap-provider"
               / "plugin" / "submarine_swaps.py").read_text()
        assert "from .jit_channel import" in src

    def test_jit_block_in_retry(self):
        src = (pathlib.Path(__file__).parent.parent / "swap-provider"
               / "plugin" / "submarine_swaps.py").read_text()
        assert "is_no_route_failure(log)" in src
        assert "open_jit_channel(" in src
        assert "wait_channel_lockin(" in src

    def test_jit_is_feature_gated(self):
        """The retry loop must check jit_enabled() before opening."""
        src = (pathlib.Path(__file__).parent.parent / "swap-provider"
               / "plugin" / "submarine_swaps.py").read_text()
        assert "jit_enabled(" in src
