"""#80 regression tests: the FUNDED-abandonment watchdog must never
cancel a hold whose swap already dispatched onchain funding.

Live evidence (2026-08-30, cln-swap-signet, ~53k sats): swap 1f3da2a6 —
17:14:39 "invoice fully funded" → "funding dispatched" (escrow onchain);
17:24:43 the #28 watchdog cancelled the parked hold ("no settle — swap
funding never completed"); 17:44:03 the client's claim machinery swept
the CONFIRMED escrow (tx b754462c, 52,931 sat) revealing the preimage;
17:44:53 the provider extracted it — but the hold no longer existed, so
_finish_normal_swap could not settle: provider paid onchain, never got
the LN side. The fix: a persistent funding_dispatched_at marker on the
HoldInvoice (set by callback_handler at the money moment) makes
dispatched holds untouchable — they park until the escrow resolves
(claim → _finish_normal_swap settles; timeout → refund → _fail_swap
cancels).

Run: python3 -m pytest tests/test_80_funded_hold_guard.py -v
"""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin.invoices import HoldInvoice, InvoiceState, Htlc, HtlcState  # noqa: E402


def _ln():
    from plugin.cln_lightning import CLNLightning
    ln = CLNLightning.__new__(CLNLightning)
    ln._logger = SimpleNamespace(
        debug=lambda *a, **k: None, info=lambda *a, **k: None,
        warning=lambda *a, **k: None, error=lambda *a, **k: None)
    ln._hold_invoices = {}
    ln._hold_invoice_callbacks = {}
    ln._tombstones = {}
    ln._bundle_main_of = {}
    ln._db = SimpleNamespace(write=lambda: None)
    return ln


def _funded_hold(payment_hash: bytes, expiry: int = 300,
                 past_grace: bool = True) -> HoldInvoice:
    inv = HoldInvoice(payment_hash=payment_hash.hex(), bolt11="lnbc1test",
                      amount_msat=1000, expiry=expiry)
    inv.funding_status = InvoiceState.FUNDED
    # one parked HTLC = the payer's money at stake
    inv.incoming_htlcs = {Htlc(state=HtlcState.ACCEPTED,
                               short_channel_id="1x1x1", channel_id=1,
                               amount_msat=1000, created_at=int(time.time()),
                               request_callback=None)}
    age = expiry * 2 + 60 if past_grace else 10
    inv.created_at = int(time.time()) - age
    return inv


class TestFundedDispatchedHoldIsUntouchable:
    def test_watchdog_leaves_a_dispatched_hold_parked(self):
        """The exact #80 shape: FUNDED, past the #28 grace, funding
        dispatched — must NOT be cancelled; the escrow resolution owns
        the exit (claim→settle / refund→cancel)."""
        ln = _ln()
        inv = _funded_hold(b"\x11" * 32)
        inv.funding_dispatched_at = int(time.time()) - 3600
        ln._hold_invoices[inv.payment_hash.hex()] = inv

        assert ln.check_invoice_expiry(inv) is False
        # untouched: still parked, still FUNDED, still registered
        assert inv.funding_status is InvoiceState.FUNDED
        assert ln._hold_invoices[inv.payment_hash.hex()] is inv
        for htlc in inv.incoming_htlcs:
            assert htlc.state is HtlcState.ACCEPTED

    def test_dispatch_marker_survives_restart_roundtrip(self):
        """The marker must persist (JsonDB) — #80 fired across a restart
        window, and a lost marker re-arms the watchdog on the funded
        hold."""
        inv = _funded_hold(b"\x22" * 32)
        inv.funding_dispatched_at = 1_700_000_000
        j = inv.to_json()
        assert j["funding_dispatched_at"] == 1_700_000_000
        restored = HoldInvoice(j)
        assert restored.funding_dispatched_at == 1_700_000_000

        # and the pre-fix record shape (field absent) still loads: None
        legacy = {k: v for k, v in j.items() if k != "funding_dispatched_at"}
        assert HoldInvoice(legacy).funding_dispatched_at is None

    def test_settle_still_completes_on_the_surviving_hold(self):
        """The heal path: with the hold alive, the claim-time preimage
        settles it — _finish_normal_swap's exact mechanism (settle on
        every ACCEPTED htlc + SETTLED status)."""
        preimage = b"\xaa" * 32
        from hashlib import sha256 as _sha256
        inv = _funded_hold(_sha256(preimage).digest())
        inv.funding_dispatched_at = int(time.time())
        inv.settle(preimage)
        assert inv.funding_status is InvoiceState.SETTLED
        for htlc in inv.incoming_htlcs:
            assert htlc.state is HtlcState.SETTLED


class TestUnfundedAbandonmentStillEnforced:
    """The #28 rationale survives untouched: a FUNDED hold whose swap
    never dispatched onchain funding (callback fired, funding failed or
    never attempted) is still abandoned after the grace window."""

    def test_watchdog_cancels_funded_hold_without_dispatch_marker(self):
        ln = _ln()
        inv = _funded_hold(b"\x44" * 32)  # past grace, no marker
        assert inv.funding_dispatched_at is None
        ln._hold_invoices[inv.payment_hash.hex()] = inv
        ln._hold_invoice_callbacks[inv.payment_hash.hex()] = lambda ph: None

        assert ln.check_invoice_expiry(inv) is True
        assert inv.funding_status is InvoiceState.FAILED
        assert inv.payment_hash.hex() not in ln._hold_invoices
        assert inv.payment_hash.hex() not in ln._hold_invoice_callbacks

    def test_watchdog_ignores_fresh_funded_hold(self):
        """Within the grace window nothing happens — dispatched or not."""
        ln = _ln()
        inv = _funded_hold(b"\x55" * 32, past_grace=False)
        inv.funding_dispatched_at = None
        assert ln.check_invoice_expiry(inv) is False
        assert inv.funding_status is InvoiceState.FUNDED


class TestSourceContract:
    """The wiring facts the object-level tests cannot reach (the
    callback handler is a long coroutine) — pinned grep-style, the same
    pattern as tests/test_import_loss.py."""

    SRC = (Path(__file__).resolve().parent.parent
           / "swap-provider" / "plugin" / "cln_lightning.py").read_text()

    def test_callback_handler_records_the_dispatch_marker(self):
        fn = self.SRC[self.SRC.index("def callback_handler"):]
        cb = fn[:fn.index("\n    def ")]
        assert "funding_dispatched_at = int(time.time())" in cb
        # persisted, not just set (restart re-arm is the #80 shape)
        assert "self.update_invoice(invoice)" in cb

    def test_the_guard_precedes_the_abandonment_cancel(self):
        assert self.SRC.index("funding_dispatched_at is not None") < \
            self.SRC.index("cancelling ABANDONED funded hold")

    def test_guard_log_names_the_issue(self):
        guard = self.SRC[self.SRC.index("#80 (live 2026-08-30"):]
        assert "#80 guard" in guard[:2000]
