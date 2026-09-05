"""Audit 2026-09-05 — pipe & lock hygiene pins (RED first, fix second).

Four findings from the 2026-09-05 audit round, each pinned here BEFORE
its fix lands (repo discipline: every live bug class gets a regression
test before the fix is considered done):

  F1 (P1) `_invoice_lock` is held across the funding dispatch:
      cln_lightning.callback_handler runs hold_invoice_callback —
      create_funding_tx (fundpsbt/signpsbt RPCs) + broadcast_funding_tx
      — INSIDE `with self._invoice_lock:` (cln_lightning.py:256), while
      plugin_htlc_accepted_hook needs the same lock on the pyln
      DISPATCH thread (cln_lightning.py:326). pyln-client 26.6.6 runs
      every method and hook inline on the single dispatch thread
      (verified on the deployed cln-swap-signet image: no threading in
      plugin.py's _dispatch_request), so a slow chain op freezes the
      ENTIRE plugin pipe — hooks, RPCs, notifications — and the #23
      thread_alive watchdog is blind to blocked-but-alive.

  F2 (P2) `swapclient` RPC blocks the dispatch thread up to 400s:
      _swapclient_swap_rpc does fut.result(timeout=400) and is
      registered background=False (single dispatch thread). It IS
      registered on server-mode boxes too (verified live:
      `lightning-cli help` on cln-swap-signet lists swapclient).

  F3 (P3) Htlc hash/eq contract mismatch: __hash__ includes created_at,
      __eq__ does not (invoices.py:106-114) — two eq-equal HTLCs hash
      differently, so set storage can hold duplicates-by-eq; only the
      find_htlc-first call order in handle_htlc keeps is_fully_funded
      (R7) honest today.

  F4 (P2) `swapprovider-orphans` is an async def RPC handler:
      pyln-client has no coroutine support (no asyncio anywhere in
      plugin.py, verified on 24.11.1 and 26.6.6), so _dispatch_request
      JSON-serializes the returned coroutine and the RPC fails. LIVE
      CONFIRMED on cln-swap-signet (deployed image reviewfixes-r1):
      `lightning-cli --signet swapprovider-orphans` returns -32600
      "JSONEncoder.default() missing 1 required positional argument:
      'o'" — the observability RPC shipped in f10b0cd has never worked.

Run: python3 -m pytest tests/test_pipe_and_lock_hygiene.py -v
"""
import asyncio
import inspect
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.cln_lightning import CLNLightning  # noqa: E402
from plugin.invoices import HoldInvoice, Htlc, HtlcState  # noqa: E402
from plugin.cln_swap_provider import CLNSwapProvider  # noqa: E402


# --------------------------------------------------------------------------
# F3 — Htlc hash/eq contract
# --------------------------------------------------------------------------

def _htlc(created_at: int) -> Htlc:
    return Htlc(state=HtlcState.ACCEPTED, short_channel_id="103x1x0",
                channel_id=1, amount_msat=100000000, created_at=created_at,
                request_callback=None)


class TestHtlcHashEqContract:
    def test_htlcs_equal_by_eq_must_hash_equal(self):
        """F3: __eq__ ignores created_at, __hash__ must too — otherwise
        set storage can hold duplicates of the same logical HTLC and
        is_fully_funded (R7 MPP sum) double-counts it."""
        a, b = _htlc(created_at=100), _htlc(created_at=200)
        assert a == b, "sanity: eq ignores created_at (replay dedup relies on it)"
        assert hash(a) == hash(b), (
            "F3: eq-equal Htlcs must hash equal — __hash__ includes "
            "created_at while __eq__ does not (invoices.py:106-114)")

    def test_set_dedup_by_identity_fields(self):
        a, b = _htlc(created_at=100), _htlc(created_at=200)
        s = {a}
        s.add(b)
        assert len(s) == 1, (
            "F3: a set must not hold two eq-equal HTLCs — the same "
            "logical HTLC would count twice in is_fully_funded")


# --------------------------------------------------------------------------
# F4 — async RPC handlers cannot serialize through pyln
# --------------------------------------------------------------------------

pyln_lightning = pytest.importorskip("pyln.client.lightning",
                                     reason="pyln-client not installed")


def _rpc_handler_names() -> list:
    return [n for n in dir(CLNSwapProvider)
            if n.startswith("_swapclient_") or n.startswith("_swapprovider_")]


class TestRpcHandlersPylnWiring:
    def test_no_rpc_handler_is_a_coroutine_function(self):
        """F4: pyln-client (24.11.1 AND deployed 26.6.6) has no coroutine
        support — an async def handler's coroutine gets JSON-serialized
        and the RPC fails at the wire. Live-confirmed for
        swapprovider-orphans on cln-swap-signet (-32600)."""
        bad = [n for n in _rpc_handler_names()
               if inspect.iscoroutinefunction(getattr(CLNSwapProvider, n))]
        assert bad == [], (
            f"F4: these RPC handlers are async def, pyln cannot dispatch "
            f"them: {bad}")

    def test_rpc_results_serialize_under_pyln_default(self):
        """F4 behavioral: whatever a handler returns with minimal state
        must survive pyln's to_json_default — a coroutine does not."""
        self_obj = SimpleNamespace(swap_client=None, swap_manager=None)
        for name in _rpc_handler_names():
            handler = getattr(CLNSwapProvider, name)
            if inspect.iscoroutinefunction(handler):
                pytest.fail(f"F4: {name} is async def (see test above)")
            result = handler(self_obj, plugin=None)
            try:
                if inspect.iscoroutine(result):
                    result.close()  # avoid un-awaited warnings
                json.dumps(result,
                           default=pyln_lightning.to_json_default)
            except TypeError as e:
                pytest.fail(
                    f"F4: {name} returned a value pyln cannot serialize "
                    f"({e!r}) — the RPC fails at the wire")


# --------------------------------------------------------------------------
# F2 — swapclient RPC must not block the pyln dispatch thread
# --------------------------------------------------------------------------

class TestSwapclientRpcDoesNotBlockDispatch:
    def test_swap_rpc_returns_while_swap_in_flight(self):
        """F2: a reverse swap runs minutes; the handler runs on the pyln
        dispatch thread (registered background=False). It must return
        promptly and answer via request.set_result later — a blocking
        fut.result() freezes the whole plugin pipe (hooks included)."""
        started = asyncio.Event()
        pending_futures = []

        class _HangingClient:
            async def reverse_swap(self, *, lightning_amount_sat, provider=None):
                started.set()
                await asyncio.sleep(3600)

        async def scenario():
            self_obj = SimpleNamespace(
                swap_client=_HangingClient(),
                _asyncio_loop=asyncio.get_running_loop())
            handler = CLNSwapProvider._swapclient_swap_rpc
            t = threading.Thread(
                target=handler, args=(self_obj,),
                kwargs={"amount_sat": 20000}, daemon=True)
            t.start()
            await asyncio.wait_for(started.wait(), timeout=5)
            # the swap coroutine is in flight; the handler thread must
            # have returned by now
            t.join(timeout=2.0)
            return t.is_alive()

        alive = asyncio.run(scenario())
        assert not alive, (
            "F2: _swapclient_swap_rpc is still blocking "
            "(fut.result(timeout=400) on the pyln dispatch thread) while "
            "the swap is in flight — every hook and RPC on the pipe is "
            "frozen behind it")


# --------------------------------------------------------------------------
# F1 — the funding dispatch must not hold _invoice_lock
# --------------------------------------------------------------------------

class _StopLoop(Exception):
    pass


def _stubbed_cln_lightning(invoice: HoldInvoice, callback) -> CLNLightning:
    """Minimal CLNLightning with stubbed deps — enough for one
    callback_handler pass over a single FUNDED hold invoice."""
    db = MagicMock()
    db.get_dict.side_effect = lambda k: {}
    db.write = MagicMock()
    plugin_instance = MagicMock()
    plugin_instance.plugin.rpc = MagicMock()
    plugin_instance.derive_secret = lambda label: b"\x11" * 32
    cln = CLNLightning(plugin_instance=plugin_instance,
                       config=SimpleNamespace(), db=db, logger=MagicMock())
    key = invoice.payment_hash.hex()
    cln._hold_invoices[key] = invoice
    cln._hold_invoice_callbacks[invoice.payment_hash] = callback
    cln.get_hold_invoice = lambda ph: cln._hold_invoices.get(ph.hex())
    cln.update_invoice = lambda inv: None  # db persistence stubbed out
    return cln


class TestFundingDispatchLockScope:
    def test_callback_handler_releases_lock_during_funding_callback(self):
        """F1: hold_invoice_callback builds + broadcasts the funding tx
        (seconds of chain RPCs). It must run OUTSIDE _invoice_lock —
        the pyln dispatch thread needs that lock to answer
        htlc_accepted, and on pyln 26 a blocked dispatch thread freezes
        the whole plugin pipe (health RPC included) while the #23
        watchdog sees a perfectly alive thread."""
        lock_free_during_callback = []

        def recording_callback(payment_hash):
            # the victim of F1 is ANOTHER thread (the pyln dispatch
            # thread in plugin_htlc_accepted_hook) — an RLock re-acquires
            # fine in the same thread, so probe cross-thread
            got_it = []

            def probe():
                if cln._invoice_lock.acquire(blocking=False):
                    cln._invoice_lock.release()
                    got_it.append(True)

            t = threading.Thread(target=probe, daemon=True)
            t.start()
            t.join(timeout=0.5)
            lock_free_during_callback.append(bool(got_it))

        invoice = HoldInvoice(
            payment_hash=b"\xab" * 32, bolt11="lnbcrt1stub",
            amount_msat=100000000, expiry=3600)
        invoice.funding_status = __import__(
            "plugin.invoices", fromlist=["InvoiceState"]).InvoiceState.FUNDED

        cln = _stubbed_cln_lightning(invoice, recording_callback)

        import plugin.cln_lightning as cl_mod
        real_sleep = cl_mod.time.sleep
        sleep_calls = {"n": 0}

        def fast_sleep(sec):
            sleep_calls["n"] += 1
            if sleep_calls["n"] >= 2:  # first pass done, stop the loop
                raise _StopLoop()
            real_sleep(0.005)

        cl_mod.time.sleep = fast_sleep
        try:
            cln.callback_handler()  # runs one pass, then _StopLoop escapes
        except _StopLoop:
            pass
        finally:
            cl_mod.time.sleep = real_sleep

        assert lock_free_during_callback == [True], (
            "F1: _invoice_lock is held while the funding callback runs "
            "(callback could not acquire it) — the pyln dispatch thread "
            "would block on the same lock inside plugin_htlc_accepted_hook")
