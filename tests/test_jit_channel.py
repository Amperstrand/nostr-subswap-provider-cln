"""JIT channel opener tests (LSP model) — validates the trigger
conditions, channel sizing, and integration into the retry loop.
"""
from __future__ import annotations

import pathlib
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin.jit_channel import (
    JIT_MAX_MULTIPLE,
    JIT_MIN_CHANNEL_SAT,
    decode_payee_node,
    has_channel_to,
    is_no_route_failure,
    jit_channel_size,
    open_jit_channel,
    sufficient_onchain,
)


class TestNoRouteDetection:
    def test_cln_205_message(self):
        """The exact CLN failure string from our mutinynet run."""
        assert is_no_route_failure(
            {"code": 205, "message": "There is no connection between source and destination at all"})

    def test_raw_string_variant(self):
        assert is_no_route_failure("Failed: We could not find a usable set of paths")

    def test_temporary_failure_is_not_no_route(self):
        """Temporary channel failures should NOT trigger JIT (a retry fixes them)."""
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


class TestChannelSizing:
    def test_minimum_applies_for_small_invoices(self):
        assert jit_channel_size(20_000) == JIT_MIN_CHANNEL_SAT

    def test_invoice_plus_buffer(self):
        size = jit_channel_size(100_000)
        assert size >= 100_000 + 1_000

    def test_capped_at_max_multiple(self):
        # a 1M invoice should not open a 10M+ channel
        size = jit_channel_size(1_000_000)
        assert size <= 1_000_000 * JIT_MAX_MULTIPLE + 1_000


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
        """CLN blocks its last 25k — the check must account for it."""
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 60_000_000, "status": "confirmed"}]  # 60k sat
        }
        # 50k channel + 25k emergency = 75k needed > 60k available
        assert not sufficient_onchain(50_000, rpc)

    def test_rpc_error_returns_false(self):
        rpc = MagicMock()
        rpc.listfunds.side_effect = Exception("rpc down")
        assert not sufficient_onchain(50_000, rpc)


class TestHasChannelTo:
    def test_existing_channel(self):
        rpc = MagicMock()
        rpc.listpeers.return_value = {
            "peers": [{"id": "abc123", "channels": [{"state": "CHANNELD_NORMAL"}]}]
        }
        assert has_channel_to("abc123", rpc)

    def test_no_channel(self):
        rpc = MagicMock()
        rpc.listpeers.return_value = {"peers": [{"id": "abc123", "channels": None}]}
        assert not has_channel_to("abc123", rpc)

    def test_rpc_error(self):
        rpc = MagicMock()
        rpc.listpeers.side_effect = Exception("boom")
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
    def test_calls_fundchannel_with_sized_amount(self):
        rpc = MagicMock()
        rpc.listfunds.return_value = {
            "outputs": [{"amount_msat": 500_000_000, "status": "confirmed"}]
        }
        rpc.fundchannel.return_value = {"txid": "abc123", "channel_id": "xyz"}
        result = open_jit_channel("03abc", 20_000, rpc)
        assert result is not None
        # verify the amount passed to fundchannel
        call_args = rpc.fundchannel.call_args
        assert "50000sat" in str(call_args)  # JIT_MIN for a 20k invoice

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


class TestRetryLoopIntegration:
    """Verifies the JIT block is present in the retry loop's source."""

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
