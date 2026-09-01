"""Issue #55 regression suite (SECURITY-REVIEW 2026-08-31 hunter-2):
aggregate over-admission — capacity probes checked CURRENT state with no
outstanding-swap reservation, so N sequential admissions over-committed
the wallet; the funding failures pushed legitimately-funded clients to
locktime refunds (availability only; park-then-claim prevents loss).

Fix contract: admission reserves the promised amount against a
pending-swap ledger, reconciled at terminal states:
  - d1 (ln_to_onchain, is_reverse=False): reserves onchain_amount while
    unfunded; released when funded (listfunds reflects the spend) or
    terminal (redeemed / failed).
  - d2 (onchain_to_ln, is_reverse=True): reserves lightning_amount while
    the payment is not observable in channel state (statuses
    pending/inflight/complete release — CLN's spendable_msat already
    nets in-flight HTLCs); RPC-unknown keeps the reservation.

Acceptance arc: over-commit goes from admitted-refund to admitted-served
— the second admission is refused while the first holds the reservation,
and is served once the first reaches a terminal state.

Run: python3 -m pytest tests/test_issue_55_reservations.py -v
"""
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402


def _mk_swap(key, *, is_reverse, onchain=80_000, lightning=80_000,
             funding_txid=None, redeemed=False, failed=False) -> SwapData:
    swap = SwapData(
        is_reverse=is_reverse, locktime=5000, onchain_amount=onchain,
        lightning_amount=lightning, redeem_script=b"\x51" * 10,
        preimage=None, prepay_hash=None, privkey=None,
        lockup_address="tb1qfake", receive_address="",
        funding_txid=funding_txid, spending_txid=None,
        is_redeemed=redeemed)
    swap._payment_hash = key
    swap.failed = failed
    return swap


def _mk_sm(swaps=None, *, can_send=100_000, spendable=100_000,
           can_receive=100_000, statuses=None) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = None  # datastore healthy (no db configured)
    sm.swaps = swaps if swaps is not None else {}
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
    sm.wallet.spendable_capacity_sat = MagicMock(return_value=spendable)
    sm.wallet.get_chain_fee = MagicMock(return_value=139)
    sm.lnworker = MagicMock()
    sm.lnworker.num_sats_can_send = MagicMock(return_value=can_send)
    sm.lnworker.num_sats_can_receive = MagicMock(return_value=can_receive)
    if statuses is None:
        statuses = {}
    sm.lnworker.get_payment_statuses = MagicMock(
        side_effect=lambda k: statuses.get(k, []))
    return sm


class TestReservationLedger:
    def test_pending_d1_reserves_onchain_amount(self):
        sm = _mk_sm({'11': _mk_swap('11', is_reverse=False, onchain=80_000)})
        assert sm._reserved_d1_onchain_sat() == 80_000

    def test_funded_d1_releases(self):
        sm = _mk_sm({'11': _mk_swap('11', is_reverse=False, funding_txid='ff' * 32)})
        assert sm._reserved_d1_onchain_sat() == 0

    def test_terminal_states_release(self):
        sm = _mk_sm({
            'aa': _mk_swap('aa', is_reverse=False, redeemed=True),
            'bb': _mk_swap('bb', is_reverse=False, failed=True),
        })
        assert sm._reserved_d1_onchain_sat() == 0

    def test_pending_d2_reserves_ln_send(self):
        sm = _mk_sm({'22': _mk_swap('22', is_reverse=True, lightning=60_000)})
        assert sm._reserved_d2_ln_send_sat() == 60_000

    def test_observable_payment_releases_d2(self):
        for live in ('pending', 'inflight', 'complete'):
            sm = _mk_sm({'22': _mk_swap('22', is_reverse=True)},
                        statuses={'22': [live]})
            assert sm._reserved_d2_ln_send_sat() == 0, live

    def test_rpc_unknown_keeps_d2_reserved(self):
        sm = _mk_sm({'22': _mk_swap('22', is_reverse=True)})
        sm.lnworker.get_payment_statuses = MagicMock(
            side_effect=Exception('listpays rpc failed'))
        assert sm._reserved_d2_ln_send_sat() == 80_000


class TestAdmissionGates:
    async def test_d2_second_admission_refused_while_first_pending(self):
        sm = _mk_sm({'22': _mk_swap('22', is_reverse=True, lightning=80_000)})
        reply = await sm.server_create_normal_swap(
            {'invoiceAmount': 30_000, 'refundPublicKey': '02' + 'ab' * 32})
        assert reply == {'error': 'not enough outgoing capacity'}

    async def test_d2_admitted_refund_to_admitted_served_arc(self):
        """#55 acceptance: with the reservation, the over-committing
        second admission is refused (first client gets served instead of
        both failing to refunds); once the first swap fails, the same
        request is admitted."""
        key = '22'
        sm = _mk_sm({key: _mk_swap(key, is_reverse=True, lightning=80_000)})
        req = {'invoiceAmount': 30_000, 'refundPublicKey': '02' + 'ab' * 32}
        assert (await sm.server_create_normal_swap(dict(req)))['error'] == \
            'not enough outgoing capacity'
        # first swap reaches a terminal state → reservation released
        sm.swaps[key].failed = True
        sm.create_reverse_swap = AsyncMock(return_value=_mk_swap('33', is_reverse=True))
        reply = await sm.server_create_normal_swap(dict(req))
        assert 'error' not in reply, reply
        sm.create_reverse_swap.assert_awaited_once()

    async def test_d1_onchain_reservation_gate(self):
        sm = _mk_sm({'11': _mk_swap('11', is_reverse=False, onchain=80_000)})
        sm._require_fresh_payment_hash = lambda ph: None
        reply = await sm.server_create_swap(
            {'type': 'reversesubmarine', 'pairId': 'BTC/BTC',
             'invoiceAmount': 30_000, 'preimageHash': 'aa' * 32,
             'claimPublicKey': '02' + 'ab' * 32})
        assert reply == {'error': 'not enough onchain balance'}

    async def test_d1_funded_swap_does_not_block_new_admission(self):
        sm = _mk_sm({'11': _mk_swap('11', is_reverse=False,
                                    funding_txid='ff' * 32)})
        sm._require_fresh_payment_hash = lambda ph: None
        sm.create_normal_swap = AsyncMock(
            return_value=(_mk_swap('44', is_reverse=False), 'inv', 'prepay'))
        reply = await sm.server_create_swap(
            {'type': 'reversesubmarine', 'pairId': 'BTC/BTC',
             'invoiceAmount': 30_000, 'preimageHash': 'aa' * 32,
             'claimPublicKey': '02' + 'ab' * 32})
        assert 'error' not in reply, reply


class TestOfferHonesty:
    def test_advertised_max_subtracts_pending_d1(self):
        """#55: the offer caps at spendable MINUS reservations, so an
        offer written while admissions are outstanding stays honest."""
        sm = _mk_sm({'11': _mk_swap('11', is_reverse=False, onchain=10_000)},
                    spendable=49_750, can_receive=10_000_000,
                    can_send=10_000_000)
        sm.normal_fee = None
        sm.percentage = Decimal('0.2')
        sm.config = SimpleNamespace(max_swap_amount=10_000_000,
                                    swapserver_fee_millionths=2000)
        sm.server_update_pairs()
        assert sm._max_amount == 39_750
