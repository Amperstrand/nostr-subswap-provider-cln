"""Regression pins for the SECURITY-REVIEW-2026-08-31 fix lane
(docs/SECURITY-REVIEW-2026-08-31.md) — every live bug class gets a test
before the fix is considered done:

1. hunter-2 `_remember_event` containment: a datastore failure while
   persisting a processed DM id must not kill the nostr consumer — the
   old code crashed the taskgroup AND never persisted the id, so relay
   replay re-crashed per event (persistent crash-loop while DMs arrive).
2. hunter-2 breaker None-hole: `last_write_monotonic` lives on
   db.storage (CLNStorage), not the JsonDB — the old read returned None
   forever, the breaker NEVER tripped. And None + failed writes must
   fail admission CLOSED (a session whose writes all fail persists
   nothing; in-memory registrations die at restart).
3. hunter-3 claim-broadcast catch-mismatch: `broadcast_raw_transaction`
   raises BitcoinCoreRPCError, not electrum's TxBroadcastError — the R3
   designated error path was dead code; failures escaped as generic
   callback errors.
4. R8-analog load guard: one malformed submarine_swaps entry must not
   keep JsonDB (and the plugin) from starting at all — skip + purge,
   loudly.
5. hunter-3 reentrancy: the three concurrent _claim_swap drivers
   serialize per-swap instead of double build+broadcast on stale outputs.

Run: python3 -m pytest tests/test_security_review_lane_20260831.py -v
"""
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
import sys
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapManager, SwapData, NostrTransport, RequestFieldError  # noqa: E402
from plugin.json_db import JsonDB  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinCoreRPCError  # noqa: E402
from plugin.cln_storage import CLNStorage, StorageReadWriteError  # noqa: E402


# ---------------------------------------------------------------------------
# 1. _remember_event containment (hunter-2)
# ---------------------------------------------------------------------------

class TestRememberEventContainment:
    def _transport(self, db) -> NostrTransport:
        nt = NostrTransport.__new__(NostrTransport)
        nt.logger = MagicMock()
        nt.sm = SimpleNamespace(db=db)
        nt.processed_event_ids = {}
        return nt

    def test_datastore_failure_does_not_raise_and_keeps_quarantine(self):
        db = MagicMock()
        db.write = MagicMock(side_effect=RuntimeError('datastore down'))
        nt = self._transport(db)
        event = SimpleNamespace(id='ab' * 32, created_at=time.time())
        nt._remember_event(event)  # used to propagate -> consumer died
        assert event.id in nt.processed_event_ids, \
            "in-memory quarantine must hold even when persistence fails"
        assert nt.logger.error.called, \
            "persistence failure must be logged loud (ERROR)"
        assert 'datastore down' in str(nt.logger.error.call_args)

    def test_success_persists_via_db_write(self):
        db = MagicMock()
        nt = self._transport(db)
        event = SimpleNamespace(id='cd' * 32, created_at=time.time())
        nt._remember_event(event)
        db.write.assert_called_once()
        assert event.id in nt.processed_event_ids

    def test_stale_entries_pruned(self):
        nt = self._transport(MagicMock())
        fresh = 'ef' * 32
        nt.processed_event_ids = {
            'stale' + '00' * 15: time.time() - 60 * 60 * 24 * 2,
            fresh: time.time(),
        }
        nt._remember_event(SimpleNamespace(id='12' * 32, created_at=time.time()))
        assert 'stale' + '00' * 15 not in nt.processed_event_ids
        assert fresh in nt.processed_event_ids


# ---------------------------------------------------------------------------
# 2. breaker None-hole (hunter-2)
# ---------------------------------------------------------------------------

def _storage(writer_ok=True, existing_data="existing"):
    """CLNStorage with stubbed datastore plumbing. Non-empty existing
    data so __init__ skips the create-key write (which would raise for
    the failing writer before we can observe the state under test)."""
    writes = []

    def writer(*, key, string, mode):
        if not writer_ok:
            raise RuntimeError('datastore down')
        writes.append(string)
        return {'key': key, 'generation': len(writes)}

    def reader(*, key):
        return {'datastore': [{'key': ['swap-provider', 'jsondb'],
                               'generation': 0, 'hex': '',
                               'string': existing_data}]}
    return CLNStorage(db_string_writer=writer, db_string_reader=reader,
                      logger=MagicMock())


def _sm_with_storage(storage) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = SimpleNamespace(storage=storage)
    return sm


class TestBreakerNoneHole:
    def test_never_written_never_failed_is_healthy(self):
        # fresh start: no success stamp yet, but nothing failed either —
        # the pre-review contract (healthy) is preserved
        sm = _sm_with_storage(_storage(writer_ok=True))
        assert sm._datastore_healthy() is True

    def test_all_writes_failed_fails_closed(self):
        # the None-hole: writes raise, no success stamp exists, the old
        # code read None off the wrong object and stayed healthy forever
        storage = _storage(writer_ok=False)
        with pytest.raises(StorageReadWriteError):
            storage.write('x')
        assert storage.failed_writes == 1
        sm = _sm_with_storage(storage)
        assert sm._datastore_healthy() is False, \
            "a session whose writes all fail must gate admission (fail closed)"

    def test_success_after_failure_recovers(self):
        storage = _storage(writer_ok=False)
        with pytest.raises(StorageReadWriteError):
            storage.write('x')
        # datastore recovers: swap in a working writer; the successful
        # write stamps last_write_monotonic and the breaker stands down
        storage.dbwriter = lambda *, key, string, mode: {
            'key': key, 'generation': 99}
        storage.write('real data')
        sm = _sm_with_storage(storage)
        assert sm._datastore_healthy() is True

    def test_freshness_window_still_governs(self, monkeypatch):
        storage = _storage(writer_ok=True)
        storage.write('x')
        sm = _sm_with_storage(storage)
        stale = storage.last_write_monotonic + 301
        monkeypatch.setattr(time, 'monotonic', lambda: stale)
        assert sm._datastore_healthy() is False

    def test_jsondb_without_storage_attr_stays_healthy(self):
        # degenerate db objects (some unit-test doubles): no storage to
        # interrogate — cannot fail closed on evidence we do not have
        sm = SwapManager.__new__(SwapManager)
        sm.db = SimpleNamespace()
        assert sm._datastore_healthy() is True

    def test_addswapinvoice_is_breaker_gated(self):
        # #47 second half: phase 2 must refuse during a datastore outage
        # like the create handlers do — an accepted registration would be
        # in-memory-only (registered=True never persists), stranding a
        # funded client on the grace-hold fail-open claim
        sm = _sm_with_storage(_storage(writer_ok=False))
        with pytest.raises(StorageReadWriteError):
            sm.db.storage.write('x')
        sm.swaps = {}
        with pytest.raises(RequestFieldError) as exc:
            sm.server_add_swap_invoice({'invoice': 'lnbc', 'refundPublicKey': ''})
        assert 'datastore unhealthy' in str(exc.value)


# ---------------------------------------------------------------------------
# 3. claim-broadcast catch-mismatch (hunter-3)
# ---------------------------------------------------------------------------

def _claim_ready_swap() -> SwapData:
    # the 21b4256e production shape (see test_expired_swap_gc): d2,
    # preimage known, funded, ready to claim — one step from broadcast
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21403,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage="a1" * 32, prepay_hash=None, privkey="01" * 32,
        lockup_address="tb1qdead", receive_address="", funding_txid="c" * 64,
        spending_txid=None, is_redeemed=False, registered=True)
    swap._payment_hash = "bb" * 32
    return swap


class _Prevout:
    def __init__(self):
        self._txid = MagicMock(hex=lambda: "e" * 64)
        self.out_idx = 0

    @property
    def txid(self):
        return self._txid

    def __hash__(self):
        return hash(("e" * 64, 0))

    def __eq__(self, other):
        return isinstance(other, _Prevout)


def _funded_txin(conf=1):
    return SimpleNamespace(
        prevout=_Prevout(), value_sats=lambda: 21403,
        block_height=None, spent_height=None, spent_txid=None)


def _claim_manager(listpays_result=None):
    swap = _claim_ready_swap()
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {swap._payment_hash: swap}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._funding_gate_deadline = {}
    sm.config = SimpleNamespace(sweep_grace_blocks=288)
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm._create_and_sign_claim_tx = MagicMock(
        return_value=MagicMock(txid=lambda: "f" * 64))
    sm.wallet = MagicMock()
    # height 4900 < locktime 5000: remaining_time stays positive so the
    # expired/_fail_swap path stays out of these claim-path tests
    sm.wallet.get_local_height = AsyncMock(return_value=4900)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.is_up_to_date = AsyncMock(return_value=True)
    sm.lnwatcher.get_addr_outputs = AsyncMock(return_value=[_funded_txin()])
    sm.lnwatcher.get_tx_height = AsyncMock(
        return_value=SimpleNamespace(conf=1))
    sm.lnworker = MagicMock()
    sm.lnworker.get_invoice = MagicMock(return_value=object())
    sm.lnworker.get_payment_statuses = MagicMock(return_value=[])
    sm.lnworker.get_preimage = MagicMock(return_value=swap.preimage)
    sm.lnworker._rpc = MagicMock()
    sm.lnworker._rpc.listpays = MagicMock(
        return_value=listpays_result or {"pays": [{"status": "pending"}]})
    return sm, swap


class TestClaimBroadcastCatchMismatch:
    async def test_bitcoin_core_rpc_error_is_caught_not_escaping(self):
        # the R3 designated error path: a broadcast failure is logged and
        # retried by the block/timer drivers — not escaped as a generic
        # callback error (the old handler caught only TxBroadcastError,
        # which broadcast_raw_transaction never raises)
        sm, swap = _claim_manager()
        sm.lnwatcher.broadcast_raw_transaction = AsyncMock(
            side_effect=BitcoinCoreRPCError('sendrawtransaction: tx bad-tx'))
        await sm._claim_swap(swap)  # used to raise out of the handler
        sm.lnwatcher.broadcast_raw_transaction.assert_awaited_once()
        assert sm.logger.error.called
        assert 'error broadcasting claim tx' in str(sm.logger.error.call_args)

    async def test_no_secret_material_in_broadcast_error_log(self):
        # issue #13 hygiene: the raw tx embeds the preimage in its
        # witness — only the txid may hit the log
        sm, swap = _claim_manager()
        sm.lnwatcher.broadcast_raw_transaction = AsyncMock(
            side_effect=BitcoinCoreRPCError('reject'))
        await sm._claim_swap(swap)
        for call in sm.logger.error.call_args_list:
            assert 'a1' * 32 not in str(call), "preimage leaked into logs"


# ---------------------------------------------------------------------------
# 4. R8-analog load guard (json_db._convert_dict)
# ---------------------------------------------------------------------------

def _good_swap_record() -> dict:
    return {'is_reverse': True, 'locktime': 5000, 'onchain_amount': 21403,
            'lightning_amount': 20000, 'redeem_script': '51' * 10,
            'preimage': 'a1' * 32, 'prepay_hash': None,
            'privkey': '01' * 32, 'lockup_address': 'tb1qdead',
            'receive_address': '', 'funding_txid': 'c' * 64,
            'spending_txid': None, 'is_redeemed': False, 'registered': True}


class TestConvertDictLoadGuard:
    def _db(self, swaps: dict) -> JsonDB:
        s = json.dumps({'submarine_swaps': swaps})
        return JsonDB(s=s, storage=SimpleNamespace(), logger=MagicMock())

    def test_malformed_entry_does_not_kill_load(self):
        # before the guard: JsonDB(...) raised straight out of
        # StoredDict.__init__ — the plugin could not start at all
        db = self._db({'aa' * 32: _good_swap_record(),
                       'bb' * 32: {'locktime': 'garbage'}})  # missing fields
        swaps = db.data['submarine_swaps']
        assert 'aa' * 32 in swaps, "the healthy record must still load"
        assert 'bb' * 32 not in swaps, "the corrupt entry must be dropped"

    def test_drop_is_loud(self):
        db = self._db({'bb' * 32: {'locktime': 'garbage'}})
        assert db.logger.error.called
        assert 'dropping corrupt' in str(db.logger.error.call_args)
        assert 'bb' * 32 in str(db.logger.error.call_args), \
            "the dropped entry's key must be named for forensics"

    def test_all_entries_corrupt_loads_empty(self):
        db = self._db({'cc' * 32: ['not', 'a', 'mapping']})
        assert dict(db.data['submarine_swaps']) == {}


# ---------------------------------------------------------------------------
# 5. per-swap claim reentrancy lock (hunter-3)
# ---------------------------------------------------------------------------

class TestClaimReentrancyLock:
    async def test_concurrent_drivers_serialize(self):
        sm, swap = _claim_manager()
        sm.lnwatcher.broadcast_raw_transaction = AsyncMock(return_value="f" * 64)
        state = {'concurrent': 0, 'max': 0}

        async def slow_outputs(address):
            state['concurrent'] += 1
            state['max'] = max(state['max'], state['concurrent'])
            await asyncio.sleep(0.02)
            state['concurrent'] -= 1
            return [_funded_txin()]

        sm.lnwatcher.get_addr_outputs = slow_outputs
        await asyncio.gather(sm._claim_swap(swap), sm._claim_swap(swap))
        assert state['max'] == 1, \
            "two drivers must not be inside _claim_swap for the same swap"

    async def test_distinct_swaps_do_not_serialize(self):
        sm, swap_a = _claim_manager()
        swap_b = _claim_ready_swap()
        swap_b._payment_hash = "cc" * 32
        sm.swaps[swap_b._payment_hash] = swap_b
        state = {'concurrent': 0, 'max': 0}

        async def slow_outputs(address):
            state['concurrent'] += 1
            state['max'] = max(state['max'], state['concurrent'])
            await asyncio.sleep(0.02)
            state['concurrent'] -= 1
            return []

        sm.lnwatcher.get_addr_outputs = slow_outputs
        await asyncio.gather(sm._claim_swap(swap_a), sm._claim_swap(swap_b))
        assert state['max'] == 2, \
            "the lock is per-swap: distinct swaps stay parallel"
