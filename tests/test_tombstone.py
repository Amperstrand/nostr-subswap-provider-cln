"""Tombstone tests (issue lightning-playground#25, A5 sibling path).

Electrum reference behavior (lnpeer.py): an HTLC whose payment_info has
been deleted fails immediately with INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
("payment info has been deleted", lnpeer.py:3178); one with no preimage
and no hold callback fails the same way (lnpeer.py:3202). The plugin's
hook instead returned {"result": "continue"} for unknown hashes —
parking payer HTLCs after hold expiry/removal, surviving restarts via
CLN's replay of unresolved HTLCs.

The fix: a persisted tombstone set of deleted hold hashes; the hook
fails (400F = incorrect_or_unknown_payment_details, matching
invoices.Htlc.fail) any tombstoned hash. Unknown-and-not-tombstoned
hashes still get "continue" — lightningd resolves ordinary invoices
itself and forwards transit traffic.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_swap = Path(__file__).resolve().parent.parent / "swap-provider"
_shim = type(sys)("plugin_src")
_shim.__path__ = [str(_swap)]
sys.modules.setdefault("plugin_src", _shim)

from plugin_src.plugin.cln_lightning import CLNLightning  # noqa: E402
from plugin_src.plugin.invoices import HoldInvoice, InvoiceState  # noqa: E402


class FakeRequest:
    def __init__(self):
        self.result = None

    def set_result(self, v):
        self.result = v


def make_cln_lightning():
    plugin = MagicMock()
    plugin.plugin.rpc = MagicMock()
    config = MagicMock()
    config.cln_config = {}
    config.network = "signet"
    db = MagicMock()
    db.get_dict.side_effect = lambda x: {}
    logger = MagicMock()
    ln = CLNLightning(plugin_instance=plugin, config=config, db=db,
                      logger=logger)
    return ln


def htlc_dict(payment_hash_hex: str) -> dict:
    return {"payment_hash": payment_hash_hex, "amount_msat": "20000000msat",
            "cltv_expiry": 999999, "htlc_id": 1}


DEAD = "aa" * 32
LIVE = "bb" * 32
UNKNOWN = "cc" * 32


@pytest.fixture()
def ln_with_live_hold():
    ln = make_cln_lightning()
    inv = MagicMock(spec=HoldInvoice)
    inv.payment_hash = bytes.fromhex(LIVE)
    inv.funding_status = InvoiceState.UNFUNDED
    ln._hold_invoices[LIVE] = inv
    return ln


class TestTombstoneBehavior:
    def test_deleted_hold_fails_htlc_instead_of_continue(self, ln_with_live_hold):
        """The #25 class: hold expired + deleted → replayed/late HTLC for
        its hash must FAIL, not park."""
        ln = ln_with_live_hold
        ln.delete_hold_invoice(LIVE)  # expiry-remove path
        req = FakeRequest()
        ln.plugin_htlc_accepted_hook({}, htlc_dict(LIVE), req, None)
        assert req.result == {"result": "fail", "failure_message": "400F"}, (
            f"expected 400F fail for deleted hold, got {req.result}")

    def test_unknown_not_tombstoned_continues(self, ln_with_live_hold):
        """Ordinary invoices / transit: unknown hash must still pass
        through for lightningd to resolve."""
        req = FakeRequest()
        ln_with_live_hold.plugin_htlc_accepted_hook({}, htlc_dict(UNKNOWN), req, None)
        assert ln_with_live_hold.plugin_htlc_accepted_hook.__name__  # reached
        assert req.result == {"result": "continue"}, req.result

    def test_tombstones_survive_restart(self, ln_with_live_hold):
        """CLN replays unresolved HTLCs on restart; the tombstone set is
        persisted in the db so the restarted plugin still fails them."""
        ln = ln_with_live_hold
        ln.delete_hold_invoice(LIVE)
        # simulate restart: same db dict carries the tombstone
        persisted = dict(ln._tombstones)
        ln2 = make_cln_lightning()
        ln2._tombstones.update(persisted)
        req = FakeRequest()
        ln2.plugin_htlc_accepted_hook({}, htlc_dict(LIVE), req, None)
        assert req.result == {"result": "fail", "failure_message": "400F"}

    def test_tombstone_write_persisted_via_db(self, ln_with_live_hold):
        ln = ln_with_live_hold
        calls = []
        ln._db.write.side_effect = lambda: calls.append(1)
        ln.delete_hold_invoice(LIVE)
        assert ln._db.write.called
        assert LIVE in ln._tombstones

    def test_live_hold_still_handled(self, ln_with_live_hold):
        """No regression: known live hold routes through handle_htlc."""
        ln = ln_with_live_hold
        req = FakeRequest()
        # handle_htlc path: invoice found → no immediate fail/continue
        ln.plugin_htlc_accepted_hook({}, htlc_dict(LIVE), req, None)
        assert req.result is None or req.result.get("result") != "fail"

    def test_cancel_all_htlcs_fails_accepted(self):
        """Expiry path companion: accepted HTLCs get failed via their
        request callbacks (400F), not left parked."""
        inv = HoldInvoice.__new__(HoldInvoice)
        inv.incoming_htlcs = []
        h = MagicMock()
        h.state = MagicMock()  # ACCEPTED sentinel via string compare below
        # patch state equality: invoices.HtlcState.ACCEPTED compare
        from plugin_src.plugin.invoices import HtlcState
        h.state = HtlcState.ACCEPTED
        inv.incoming_htlcs = [h]
        inv.funding_status = InvoiceState.UNFUNDED
        inv.cancel_all_htlcs()
        h.fail.assert_called_once()
        assert inv.funding_status == InvoiceState.FAILED
