"""Issue #53 regression suite (SECURITY-REVIEW 2026-08-31 hunter-2):
error-distinction stragglers of the #21 action-contract class, plus the
latent NameError that made the EXISTING dialects dead code:

  0. CapacityProbeError was imported TYPE_CHECKING-only — `except`
     clauses evaluate the name when an exception FIRES, so the probe
     handlers raised NameError at exactly the moment an RPC outage hit.
  1. spendable_capacity_sat's plain Exception (listfunds outage in
     balance_sat) sat outside any handler → 'internal error serving
     createswap'.
  2. RouteHintUnavailableError / DuplicateInvoiceCreationError /
     Bolt11InvoiceCreationError landed in the same generic bucket.
  3. RPC-OK with zero suitable channels still EMITTED a hint-less
     invoice (the R9 inversion onto the payer).

Run: python3 -m pytest tests/test_issue_53_error_dialects.py -v
"""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402
from plugin.cln_lightning import (CLNLightning, CapacityProbeError,  # noqa: E402
                                  RouteHintUnavailableError,
                                  Bolt11InvoiceCreationError)
from plugin.invoices import DuplicateInvoiceCreationError  # noqa: E402

REQ = {'type': 'reversesubmarine', 'pairId': 'BTC/BTC',
       'invoiceAmount': 50000, 'preimageHash': 'aa' * 32,
       'claimPublicKey': '02' + 'ab' * 32}


def _mk_swap_d1() -> SwapData:
    swap = SwapData(
        is_reverse=False, locktime=5000, onchain_amount=21181,
        lightning_amount=50000, redeem_script=b"\x51" * 10,
        preimage=None, prepay_hash=None, privkey=None,
        lockup_address="tb1qfake", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = 'aa' * 32
    return swap


def _mk_sm() -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = None  # _datastore_healthy: no db configured → True
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm._claim_bump_counts = {}
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm._min_amount = 1000
    sm._max_amount = 10_000_000
    sm.config = SimpleNamespace(max_swap_amount=10_000_000)
    sm.wallet = MagicMock()
    sm.wallet.spendable_capacity_sat = MagicMock(return_value=10_000_000)
    sm.lnworker = MagicMock()
    sm.lnworker.num_sats_can_receive = MagicMock(return_value=10_000_000)
    sm._require_fresh_payment_hash = lambda ph: None
    sm._create_and_sign_claim_tx = MagicMock()
    return sm


class TestProbeHandlerDialects:
    async def test_ln_probe_outage_reply_not_nameerror(self):
        """The latent NameError regression: pre-fix, this exact scenario
        raised NameError(CapacityProbeError) instead of the typed reply."""
        sm = _mk_sm()
        sm.lnworker.num_sats_can_receive = MagicMock(
            side_effect=CapacityProbeError('listfunds rpc failed'))
        reply = await sm.server_create_swap(dict(REQ))
        assert reply == {'error': 'capacity probe failed — try again shortly'}

    async def test_onchain_probe_outage_distinct_reply(self):
        sm = _mk_sm()
        sm.wallet.spendable_capacity_sat = MagicMock(
            side_effect=Exception('CLNChainWallet: balance_sat failed to '
                                  'call listfunds rpc: boom'))
        reply = await sm.server_create_swap(dict(REQ))
        assert reply == {'error': 'onchain capacity probe failed — try again shortly'}


class TestInvoiceCreationDialects:
    async def test_route_hint_unavailable_reply(self):
        sm = _mk_sm()
        sm.create_normal_swap = AsyncMock(
            side_effect=RouteHintUnavailableError(
                'no suitable channels for route hint (0 of 3 channels usable)'))
        reply = await sm.server_create_swap(dict(REQ))
        assert 'no routable channels' in reply['error']

    async def test_duplicate_invoice_reply(self):
        sm = _mk_sm()
        sm.create_normal_swap = AsyncMock(side_effect=DuplicateInvoiceCreationError(
            'b11invoice_from_hash: invoice already exists in cln'))
        reply = await sm.server_create_swap(dict(REQ))
        assert 'invoice already exists' in reply['error']

    async def test_signing_failure_reply(self):
        sm = _mk_sm()
        sm.create_normal_swap = AsyncMock(side_effect=Bolt11InvoiceCreationError(
            'signinvoice rpc failed: boom'))
        reply = await sm.server_create_swap(dict(REQ))
        assert reply == {'error': 'invoice creation failed — try again shortly'}


class _Rpc:
    def __init__(self, channels=None, fail=False):
        self.channels = channels
        self.fail = fail

    def listpeerchannels(self):
        if self.fail:
            raise Exception('connection refused')
        return {'channels': self.channels}


def _ln(rpc) -> CLNLightning:
    ln = CLNLightning.__new__(CLNLightning)
    ln._logger = MagicMock()
    ln._rpc = rpc
    ln._config = SimpleNamespace(network='signet')
    return ln


_HEALTHY_CHAN = {
    'state': 'CHANNELD_NORMAL', 'short_channel_id': '319019x96x0',
    'peer_id': '02' + 'ab' * 32, 'receivable_msat': 5_000_000,
    'updates': {'remote': {'fee_base_msat': 1, 'fee_proportional_millionths': 10,
                           'cltv_expiry_delta': 6}},
}


class TestZeroSuitableChannelsRefusal:
    def test_healthy_channel_still_hints(self):
        ln = _ln(_Rpc([_HEALTHY_CHAN]))
        hints = ln._get_route_hints(50000 * 1000)
        assert len(hints) == 1  # control: the refusal must not over-fire

    def test_zero_suitable_raises_not_hintless(self):
        """R9 inversion: RPC-OK + zero usable channels must REFUSE, not
        emit an unroutable hint-less invoice."""
        dead = dict(_HEALTHY_CHAN, state='CHANNELD_AWAITING_LOCKIN')
        ln = _ln(_Rpc([dead]))
        with pytest.raises(RouteHintUnavailableError, match='no suitable channels'):
            ln._get_route_hints(50000 * 1000)

    def test_gossip_incomplete_channels_raise_not_hintless(self):
        """channels exist but none carries remote updates → same refusal
        (the skip-path also empties the hint list)."""
        partial = dict(_HEALTHY_CHAN)
        partial['updates'] = {}
        ln = _ln(_Rpc([partial]))
        with pytest.raises(RouteHintUnavailableError, match='no suitable channels'):
            ln._get_route_hints(50000 * 1000)

    def test_rpc_failure_keeps_distinct_message(self):
        ln = _ln(_Rpc(fail=True))
        with pytest.raises(RouteHintUnavailableError, match='cannot probe'):
            ln._get_route_hints(50000 * 1000)
