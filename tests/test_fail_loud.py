"""Fail-loud core (audit round 4): issue #16 reachable crash policy,
issue #17 supervised background tasks with per-subsystem death policies,
issue #20 offer withdrawal while the nostr transport is dead, issue #22
persistence discipline on swap-state mutations with on-chain effect.

Kill-injection style: exceptions are injected into stubbed subsystems and
the DEATH POLICY is asserted (ERROR log + os._exit for fatal subsystems,
restart/requeue for recoverable ones). os._exit is always monkeypatched —
nothing here can kill the test runner.

Run: python3 -m pytest tests/test_fail_loud.py -v
"""
import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin import submarine_swaps as ss  # noqa: E402
from plugin import chain_monitor as cm_mod  # noqa: E402
from plugin.chain_monitor import ChainMonitor  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData, NostrTransport  # noqa: E402
from plugin.utils import supervise, fatal_exit  # noqa: E402
from plugin.bitcoin_core_rpc import BitcoinCoreRPC  # noqa: E402

_real_asyncio = asyncio


class _AsyncioNoSleep:
    """Proxy that delegates everything to asyncio except sleep, which is
    instant — lets the forever-loops run at test speed."""
    def __getattr__(self, name):
        return getattr(_real_asyncio, name)

    @staticmethod
    async def sleep(_seconds):
        await _real_asyncio.sleep(0.005)


def _d2_swap(funding_txid=None) -> SwapData:
    swap = SwapData(
        is_reverse=True, locktime=5000, onchain_amount=21181,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=b"\xa1" * 32, prepay_hash=None, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid=funding_txid,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


def _sm(**attrs) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.is_initialized = asyncio.Event()
    sm.lnworker = MagicMock()
    sm.lnworker._hold_invoice_callbacks = {}
    sm.lnworker.get_hold_invoice = MagicMock(return_value=None)
    for k, v in attrs.items():
        setattr(sm, k, v)
    return sm


class TestSuperviseHelper:
    async def test_logs_error_and_routes_policy(self):
        logger = MagicMock()
        deaths = []

        async def boom():
            raise RuntimeError("injected death")

        task = supervise(_real_asyncio.create_task(boom()),
                         logger=logger, name="stub", on_death=deaths.append)
        with pytest.raises(RuntimeError):
            await task
        assert logger.error.call_count == 1
        logged = logger.error.call_args.args[0]
        assert "supervised task 'stub' died" in logged
        assert "RuntimeError: injected death" in logged  # traceback carried
        assert len(deaths) == 1 and isinstance(deaths[0], RuntimeError)

    async def test_silent_on_cancel_and_clean_exit(self):
        logger = MagicMock()

        async def clean():
            return 42

        clean_task = supervise(_real_asyncio.create_task(clean()),
                               logger=logger, name="clean")
        assert await clean_task == 42
        assert logger.error.call_count == 0

        hang = _real_asyncio.Event()

        async def waiter():
            await hang.wait()

        cancelled = supervise(_real_asyncio.create_task(waiter()),
                              logger=logger, name="cancelled")
        cancelled.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await cancelled
        assert logger.error.call_count == 0


class TestFatalExit:
    def test_logs_and_hard_exits_nonzero(self, monkeypatch):
        exits = []
        monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
        logger = MagicMock()
        fatal_exit("policy: dying loudly", logger=logger)
        assert exits == [1]
        logger.error.assert_called_once_with("policy: dying loudly")

    def test_stderr_fallback_without_logger(self, monkeypatch, capsys):
        exits = []
        monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
        fatal_exit("no logger here")
        assert exits == [1]
        assert "ERROR: no logger here" in capsys.readouterr().err


class TestChainMonitorDeathPolicy:
    """#17 policy for the chain watch: FATAL — an escaped death must hit
    the #16 crash policy (ERROR log + os._exit), never silent."""

    def _monitor(self):
        # built via __new__: sibling tests stub sys.modules['bitcoinrpc']
        # before this module imports (collection order), so
        # BitcoinCoreRPC.__init__ cannot run here — set the state
        # monitoring_loop/run actually use
        mon = object.__new__(ChainMonitor)
        mon.callbacks = {}
        mon.monitoring_task = None
        mon._logger = MagicMock()
        return mon

    async def test_escaped_death_is_fatal(self, monkeypatch):
        monkeypatch.setattr(BitcoinCoreRPC, "_init", AsyncMock(return_value=None))
        exits = []
        monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
        mon = self._monitor()

        # a plain BaseException subclass: escapes the loop's `except
        # Exception` (a death) without stdlib's KeyboardInterrupt/
        # SystemExit loop-teardown special-casing
        class InjectedBaseDeath(BaseException):
            pass

        async def dead_rpc():
            raise InjectedBaseDeath("injected: bitcoind thread nuked")

        mon.get_local_height = dead_rpc
        await mon.run()  # spawns the supervised monitoring task
        for _ in range(100):
            if exits:
                break
            await _real_asyncio.sleep(0.01)
        assert exits == [1], "chain-watch death must hard-exit (#16 policy)"
        err = [c.args[0] for c in mon._logger.error.call_args_list]
        assert any("supervised task 'chain-monitor' died" in m for m in err)
        assert any("chain-watch (monitoring_loop) died" in m for m in err)

    async def test_startup_rpc_failure_retries_inside_loop(self, monkeypatch):
        """#17: the initial height fetch is inside the retry loop now — a
        bitcoind hiccup at start is an ERROR log + retry, NOT a death."""
        monkeypatch.setattr(cm_mod, "asyncio", _AsyncioNoSleep())
        mon = self._monitor()
        heights = iter([None, None])  # first pass fails, second succeeds

        async def flaky_height():
            if next(heights, "done") is None:
                raise RuntimeError("bitcoind temporarily down")

        mon.get_local_height = flaky_height
        fired = []

        async def cb():
            fired.append(1)

        mon.callbacks["tb1qfake"] = cb
        mon._heights_seen = []

        async def height_seq():
            pass

        # drive the loop: pass 1 raises (baseline fails), pass 2 returns
        # baseline, pass 3 sees a new block -> trigger_callbacks
        seq = iter([RuntimeError("bitcoind temporarily down"), 100, 101, 101])

        async def scripted_height():
            v = next(seq)
            if isinstance(v, Exception):
                raise v
            mon._heights_seen.append(v)
            return v

        mon.get_local_height = scripted_height
        task = _real_asyncio.create_task(mon.monitoring_loop())
        for _ in range(200):
            if fired:
                break
            await _real_asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await task
        assert mon._heights_seen == [100, 101]  # baseline then new block
        assert fired == [1]  # callback fired exactly once, on the new block
        assert task.cancelled()  # ended by OUR cancel, never by a death
        assert mon._logger.error.call_count == 1  # the startup RPC failure


class TestNostrWithdrawal:
    """#20: when the DM consumer dies the offer is withdrawn (no more
    republishes) and new swap requests are refused until restart."""

    async def test_transport_death_withdraws_and_restarts(self, monkeypatch):
        events = {"publishes": 0, "withdrawals": 0, "stops": 0}

        class FakeTransport:
            def __init__(self, config, sm):
                self.sm = sm
                self.is_connected = asyncio.Event()
                self.dead = asyncio.Event()

            def __enter__(self):
                self.is_connected.set()
                return self

            def __exit__(self, *a):
                events["stops"] += 1
                self.sm.is_initialized.clear()

            async def publish_offer(self):
                events["publishes"] += 1
                self.sm.is_initialized.set()
                # issue #20 injection: the consumer dies mid-announce
                self.dead.set()

        monkeypatch.setattr(ss, "NostrTransport", FakeTransport)
        monkeypatch.setattr(ss, "asyncio", _AsyncioNoSleep())
        sm = _sm()
        sm.config = SimpleNamespace(nostr_relays=[])
        sm.server_update_pairs = MagicMock()
        sm._max_amount = 100
        server = _real_asyncio.create_task(sm.run_nostr_server())
        for _ in range(400):
            if events["withdrawals"] >= 2 and events["publishes"] >= 3:
                break
            await _real_asyncio.sleep(0.005)
        server.cancel()
        with pytest.raises(_real_asyncio.CancelledError):
            await server
        # withdrawal ERROR logged each death, offer flag cleared, and the
        # recoverable policy RESTARTED the transport (fresh publishes)
        withdrawal_logs = [c.args[0] for c in sm.logger.error.call_args_list
                           if "withdrawing offer" in c.args[0]]
        assert len(withdrawal_logs) >= 2
        assert events["stops"] >= 2  # with-block exited = teardown each death
        assert events["publishes"] >= 3  # restart happened
        assert not sm.is_initialized.is_set()

    async def test_handle_request_refuses_while_down(self):
        t = object.__new__(NostrTransport)
        sm = _sm()
        sm.is_server = True
        sm.server_add_swap_invoice = MagicMock(return_value={"ok": 1})
        t.sm = sm
        t.logger = MagicMock()
        replies = []

        async def send(pubkey, content):
            replies.append(content)
            return "re"

        t.send_direct_message = send
        req = {"method": "addswapinvoice", "invoice": "lnbcrt-x",
               "refundPublicKey": "00" * 33, "event_id": "ev1",
               "event_pubkey": "aa" * 32}

        await t.handle_request(dict(req))
        assert "unavailable" in replies[-1]  # refused loudly while down
        sm.server_add_swap_invoice.assert_not_called()

        sm.is_initialized.set()
        await t.handle_request(dict(req))
        sm.server_add_swap_invoice.assert_called_once()  # served when up


class TestPaymentLoopPolicy:
    """#17 policy for the payment loop: RECOVERABLE — a buggy payment
    attempt is logged at ERROR and re-queued, never escalated."""

    async def test_payment_death_requeues_with_backoff(self):
        sm = _sm()
        key = (b"\xcc" * 32).hex()
        sm.invoices_to_pay[key] = 1000000000000  # the in-flight lock

        async def buggy(_k):
            raise RuntimeError("injected payment bug")

        sm.pay_pending_ln_invoice = buggy
        before = ss.now()
        await sm._supervised_pay_invoice(key)
        after = ss.now()
        assert sm.logger.error.call_count == 1
        assert "payment task" in sm.logger.error.call_args.args[0]
        # lock released to a ~60s retry instead of stuck-forever
        assert before + 60 <= sm.invoices_to_pay[key] <= after + 60


class TestFailSwapWatcher:
    """#22 (audit F23): a failed swap with live on-chain funding keeps its
    chain watch — the sweep/refund branch needs it until the record goes."""

    def _recorder(self):
        watch = SimpleNamespace(removed=[], callbacks={})

        def remove_callback(addr):
            watch.removed.append(addr)

        watch.remove_callback = remove_callback
        return watch

    def test_funded_swap_keeps_watcher(self):
        swap = _d2_swap(funding_txid="ab" * 32)
        sm = _sm(lnwatcher=self._recorder())
        sm.swaps[swap._payment_hash] = swap
        sm._fail_swap(swap, "invoice unpayable after 15 attempts")
        assert sm.lnwatcher.removed == []  # F23: watcher must survive
        assert swap._payment_hash in sm.swaps  # record stays too
        assert sm.db.write.called  # and the failure is persisted

    def test_unfunded_swap_drops_watcher(self):
        swap = _d2_swap(funding_txid=None)
        sm = _sm(lnwatcher=self._recorder())
        sm.swaps[swap._payment_hash] = swap
        sm._fail_swap(swap, "expired")
        assert sm.lnwatcher.removed == [swap.lockup_address]
        assert swap._payment_hash not in sm.swaps


class TestPersistenceDiscipline:
    """#22 (audit F10): on-chain-effect mutations are flushed to the db
    immediately, in the right order relative to the on-chain effect."""

    def _claim_manager(self):
        sm = _sm()
        sm.config = SimpleNamespace(sweep_grace_blocks=288)
        sm.wallet = MagicMock()
        sm.wallet.get_local_height = AsyncMock(return_value=100)
        sm.wallet.get_chain_fee = MagicMock(return_value=300)
        events = []
        sm.db.write = MagicMock(side_effect=lambda: events.append("write"))

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

        class _Lnwatcher:
            async def is_up_to_date(self):
                return True

            async def get_addr_outputs(self, address):
                txin = SimpleNamespace(
                    prevout=_Prevout(),
                    value_sats=lambda: 21181, spent_height=None, spent_txid=None)
                return [txin]

            async def get_tx_height(self, txid):
                return SimpleNamespace(conf=1)

            async def broadcast_raw_transaction(self, raw):
                events.append("broadcast")
                return "f" * 64

        sm.lnwatcher = _Lnwatcher()
        # committed swap: an in-flight payment counts as LN commitment
        sm.lnworker.get_invoice = MagicMock(return_value=None)
        sm.lnworker.get_payment_statuses = MagicMock(return_value=["pending"])
        sm.lnworker.get_preimage = MagicMock(return_value=None)
        fake_tx = MagicMock()
        fake_tx.txid = lambda: "f" * 64
        sm._create_and_sign_claim_tx = MagicMock(return_value=fake_tx)
        # #26 park-then-claim: the payer-side listpays must report the
        # payment parked/settled, else the claim defers before signing
        sm.lnworker._rpc = MagicMock()
        sm.lnworker._rpc.listpays = MagicMock(
            return_value={"pays": [{"status": "complete"}]})
        return sm, events

    async def test_claim_persisted_before_broadcast(self):
        sm, events = self._claim_manager()
        swap = _d2_swap()
        sm.swaps[swap._payment_hash] = swap
        await sm._claim_swap(swap)
        assert events.index("write") < events.index("broadcast"), \
            "claim intent (spending_txid) must be on disk BEFORE the broadcast"
        assert swap.spending_txid == "f" * 64

    def test_funding_persisted_after_broadcast(self):
        sm = _sm()
        events = []
        sm.wallet = MagicMock()
        sm.wallet.broadcast_transaction = MagicMock(
            side_effect=lambda tx: events.append("broadcast"))
        sm.db.write = MagicMock(side_effect=lambda: events.append("write"))
        swap = _d2_swap()
        sm.broadcast_funding_tx(swap, MagicMock())
        assert events == ["broadcast", "write"], \
            "funding_txid is flushed AFTER the broadcast (a pre-broadcast " \
            "write would make the one-shot funding callback skip re-broadcast)"
