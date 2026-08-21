"""P0 regression tests for GitHub issues #2 and #3 (audit AUDIT-4 D-1,
audit AUDIT-3 PD-1). Each test reproduces the audited loss mechanism
against the real classes — no mocks of the unit under test.

Run: python3 -m pytest tests/test_p0_fixes.py -v
"""
import sys
import time
from hashlib import sha256 as _hl_sha256
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin.invoices import HoldInvoice, InvoiceState  # noqa: E402
from plugin.transaction import Transaction, TxInput, TxOutpoint  # noqa: E402
from plugin.submarine_swaps import SwapData  # noqa: E402


def _witness(*elements: bytes) -> bytes:
    """Serialize a witness stack the way TxInput.witness_elements parses it:
    compact_size(n) + per-element compact_size(len) + bytes."""
    out = bytes([len(elements)])
    for el in elements:
        assert len(el) < 253
        out += bytes([len(el)]) + el
    return out


def _input(witness: bytes = None) -> TxInput:
    return TxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=0),
                   script_sig=b"", witness=witness)


def _claim_tx(*inputs: TxInput):
    return SimpleNamespace(inputs=lambda: list(inputs))


def _swap(preimage: bytes) -> SwapData:
    swap = SwapData(
        is_reverse=False, locktime=1000, onchain_amount=50850,
        lightning_amount=60000, redeem_script=b"\x51" * 10, preimage=None,
        prepay_hash=None, privkey=b"\x01" * 32, lockup_address="",
        receive_address="", funding_txid=None, spending_txid=None,
        is_redeemed=False)
    swap._payment_hash = _hl_sha256(preimage).hexdigest()
    return swap


# ================================================================ issue #2
# Preimage extraction must survive legacy/short-witness inputs in the
# client's claim tx (electrum guards this; we didn't — full onchain_amount
# loss per attack).

class TestExtractPreimageIssue2:
    def test_legacy_input_first_does_not_crash_and_finds_preimage(self):
        from plugin.submarine_swaps import SwapManager
        preimage = b"\xa1" * 32
        swap = _swap(preimage)
        claim = _claim_tx(
            _input(),                              # legacy: no witness
            _input(_witness(b"\x00" * 8)),         # short witness (1 element)
            _input(_witness(b"\x02" * 71, preimage)),  # the HTLC claim
        )
        assert SwapManager.extract_preimage(swap, claim) == preimage

    def test_no_matching_input_returns_none(self):
        from plugin.submarine_swaps import SwapManager
        swap = _swap(b"\xbb" * 32)
        claim = _claim_tx(
            _input(),
            _input(_witness(b"\x02" * 71, b"\xcc" * 32)),  # wrong preimage
        )
        assert SwapManager.extract_preimage(swap, claim) is None

    def test_witness_elements_empty_for_legacy_input(self):
        # pins the transaction.py primitive the guard relies on
        assert _input().witness_elements() == []
        assert _input(_witness(b"\x00")).witness_elements() == [b"\x00"]


# ================================================================ issue #3
# A FUNDED main whose prepay expired (sweeper deleted it) must NOT have its
# callback fired — the swap must be torn down instead (payer's main HTLCs
# failed immediately, R5), never funded without the prepay.

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


def _expired_unfunded_hold(payment_hash: bytes, expiry: int = 300) -> HoldInvoice:
    inv = HoldInvoice(payment_hash=payment_hash.hex(), bolt11="lnbc1test",
                      amount_msat=1000, expiry=expiry)
    inv.created_at = int(time.time()) - expiry - 1
    return inv


class TestPrepayExpiryTeardownIssue3:
    def test_expiring_prepay_cancels_funded_main_and_disarms_callback(self):
        from plugin.cln_lightning import CLNLightning
        ln = _ln()
        main = HoldInvoice(payment_hash=(b"\x11" * 32).hex(), bolt11="lnbc1m",
                           amount_msat=19_000_000, expiry=300)
        main.incoming_htlcs = set()  # payer's parked HTLCs
        main.funding_status = InvoiceState.FUNDED
        prepay = _expired_unfunded_hold(b"\x22" * 32)
        main.attach_prepay_invoice(prepay.payment_hash)

        ln._hold_invoices[main.payment_hash.hex()] = main
        ln._hold_invoices[prepay.payment_hash.hex()] = prepay
        fired = []
        ln._hold_invoice_callbacks[main.payment_hash.hex()] = \
            lambda ph: fired.append(ph)

        # bundle recorded (what bundle_payments will maintain)
        ln._bundle_main_of[prepay.payment_hash.hex()] = main.payment_hash.hex()

        expired = ln.check_invoice_expiry(prepay)
        assert expired, "sweeper must process the expired prepay"
        # payer's main payment returned immediately, callback disarmed:
        assert main.funding_status is InvoiceState.FAILED
        assert main.payment_hash not in ln._hold_invoice_callbacks
        assert not fired, "funding callback must NOT fire without the prepay"
        # both holds gone, reverse index cleaned:
        assert prepay.payment_hash.hex() not in ln._hold_invoices
        assert main.payment_hash.hex() not in ln._hold_invoices
        assert prepay.payment_hash.hex() not in ln._bundle_main_of

    def test_expiring_unfunded_main_still_cancels_its_prepay(self):
        # pre-existing symmetric behavior must not regress
        ln = _ln()
        main = _expired_unfunded_hold(b"\x33" * 32)
        prepay = HoldInvoice(payment_hash=(b"\x44" * 32).hex(), bolt11="lnbc1p",
                             amount_msat=1_000, expiry=300)
        main.attach_prepay_invoice(prepay.payment_hash)
        ln._hold_invoices[main.payment_hash.hex()] = main
        ln._hold_invoices[prepay.payment_hash.hex()] = prepay
        ln._bundle_main_of[prepay.payment_hash.hex()] = main.payment_hash.hex()

        assert ln.check_invoice_expiry(main) is True
        assert main.payment_hash.hex() not in ln._hold_invoices
        assert prepay.payment_hash.hex() not in ln._hold_invoices

    def test_callback_none_prepay_is_abort_not_proceed(self):
        # the callback gate: prepay None must be ABORT (never fund), prepay
        # FUNDED -> PROCEED, prepay present unfunded -> WAIT, no prepay
        # attached -> PROCEED (non-bundled invoices are single-set)
        from plugin.invoices import HoldInvoice
        from plugin.cln_lightning import CLNLightning, PrepayGate
        ln = _ln()
        main = HoldInvoice(payment_hash=(b"\x55" * 32).hex(), bolt11="x",
                           amount_msat=1000, expiry=300)
        main.attach_prepay_invoice(b"\x66" * 32)
        assert ln._bundle_prepay_state(main, None) is PrepayGate.ABORT
        prepay_funded = HoldInvoice(payment_hash=(b"\x66" * 32).hex(),
                                    bolt11="x", amount_msat=10, expiry=300)
        prepay_funded.funding_status = InvoiceState.FUNDED
        assert ln._bundle_prepay_state(main, prepay_funded) is PrepayGate.PROCEED
        prepay_unfunded = HoldInvoice(payment_hash=(b"\x77" * 32).hex(),
                                      bolt11="x", amount_msat=10, expiry=300)
        assert ln._bundle_prepay_state(main, prepay_unfunded) is PrepayGate.WAIT
        assert ln._bundle_prepay_state(None, prepay_funded) is PrepayGate.WAIT
