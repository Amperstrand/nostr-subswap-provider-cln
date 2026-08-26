"""Backlog fixes for issues #4 (BOLT #11 reader MUSTs), #5 (PD-2
settled-prepay deadlock), #6 (PD-3 sweeper starvation / callback-less
HTLCs), #7 (D-2 underfund guard both directions). RED-first.

Run: python3 -m pytest tests/test_backlog_fixes.py -v
"""
import inspect
import re
import sys
import time
from hashlib import sha256 as _hl
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

from electrum_ecc import ECPrivkey  # noqa: E402

from plugin import constants as plugin_constants  # noqa: E402
from plugin.constants import BitcoinSignet  # noqa: E402
from plugin.invoices import HoldInvoice, Htlc, HtlcState, InvoiceState  # noqa: E402
from plugin.lnaddr import (LnDecodeException, bech32_decode, convertbits,  # noqa: E402
                           int_to_data5, lndecode, tagged5)
from plugin.segwit_addr import Encoding, bech32_encode  # noqa: E402
from plugin.submarine_swaps import RequestFieldError  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

_SIGN_PRIV = ECPrivkey(bytes(range(1, 33)))


def _build_invoice(tags5, hrp="lntbs", date=1700000000):
    """Assemble a SIGNED bolt11 string with arbitrary raw 5-bit tag
    payloads — lets tests express shapes the encoder refuses to emit
    (wrong lengths, duplicate tags)."""
    data5 = list(int_to_data5(date, bit_len=35))
    for ch, payload in tags5:
        data5 += tagged5(ch, list(payload))
    body = data5  # unsigned part
    data8 = bytes(convertbits(list(body), 5, 8, True))
    hrp_hash = _hl(hrp.encode("ascii") + data8).digest()
    sig65 = _SIGN_PRIV.ecdsa_sign_recoverable(hrp_hash, is_compressed=True)
    wire_sig = sig65[1:] + bytes([sig65[0] - 27 - 4])  # sig64 || recid
    data5 += list(convertbits(wire_sig, 8, 5, True))
    return bech32_encode(Encoding.BECH32, hrp, data5)


def _bits8(data: bytes):
    return list(convertbits(data, 8, 5, True))


P32 = _bits8(bytes(32))          # 52 groups — correct length for p/s
D_TAG = _bits8(b"test")          # valid utf-8 d


# ================================================================ issue #4
# Ported electrum architecture: decode stays LENIENT (wrong-length tags →
# unknown_tags — old invoices must stay parseable); the four reader MUSTs
# are enforced at the ACTION BOUNDARY (electrum: lnworker
# _check_bolt11_invoice + validate_features). Our boundary is
# check_invoice_before_payment, called by server_add_swap_invoice before
# any state mutation — a malformed invoice fails at the API, not after
# the client's onchain lockup.
class TestReaderMustsIssue4:
    def setup_method(self):
        self._old = plugin_constants.net
        plugin_constants.net = BitcoinSignet()

    def teardown_method(self):
        plugin_constants.net = self._old

    def _check(self, tags5):
        # eager imports: a missing impl must ERROR the test, not pass it
        from plugin.submarine_swaps import (RequestFieldError,
                                            check_invoice_before_payment)
        try:
            return check_invoice_before_payment(_build_invoice(tags5))
        except RequestFieldError:
            raise
        except Exception as e:
            raise AssertionError(
                f"boundary check must reject with RequestFieldError "
                f"(maps to a clean API error), got {type(e).__name__}: {e}")

    def test_decode_stays_lenient_wrong_length_p(self):
        # electrum-parity: parser must NOT raise on malformed-but-stored
        # invoices (bolt11.py:515-544 pattern)
        inv = _build_invoice([("p", _bits8(bytes(16))), ("d", D_TAG), ("s", P32)])
        addr = lndecode(inv)
        assert ("p",) == (addr.unknown_tags[0][0],)

    def test_wrong_length_p_rejected_at_boundary(self):
        # BOLT #11: MUST fail the payment if any field with fixed
        # data_length (p, h, s, n) does not have the correct length.
        with pytest.raises(RequestFieldError):
            self._check([("p", _bits8(bytes(16))), ("d", D_TAG), ("s", P32)])

    def test_wrong_length_s_rejected_at_boundary(self):
        with pytest.raises(RequestFieldError):
            self._check([("p", P32), ("d", D_TAG), ("s", _bits8(bytes(16)))])

    def test_both_d_and_h_rejected_at_boundary(self):
        with pytest.raises(RequestFieldError):
            self._check([("p", P32), ("d", D_TAG), ("h", P32), ("s", P32)])

    def test_neither_d_nor_h_rejected_at_boundary(self):
        with pytest.raises(RequestFieldError):
            self._check([("p", P32), ("s", P32)])

    def test_missing_s_rejected_at_boundary(self):
        # BOLT #11: if a valid `s` field is not provided: MUST fail the payment.
        with pytest.raises(RequestFieldError):
            self._check([("p", P32), ("d", D_TAG)])

    def test_unknown_even_feature_bit_rejected_at_boundary(self):
        # BOLT #11: unknown even bits non-zero → MUST fail the payment.
        # (1 << 40 is unassigned — electrum validate_features semantics.)
        with pytest.raises(RequestFieldError):
            self._check([("p", P32), ("d", D_TAG), ("s", P32),
                         ("9", list(int_to_data5(1 << 40)))])

    def test_our_own_feature_set_accepted(self):
        # positive control: exactly what b11invoice_from_hash emits
        feats = (1 << 8) | (1 << 14) | (1 << 17)
        addr = self._check([("p", P32), ("d", D_TAG), ("s", P32),
                            ("9", list(int_to_data5(feats)))])
        assert addr.paymenthash == bytes(32)

    def test_electrum_style_odd_bits_accepted(self):
        # electrum client invoices carry odd/optional bits (9, 15, 17,
        # 151 trampoline) — must stay payable
        feats = (1 << 9) | (1 << 15) | (1 << 17) | (1 << 151)
        addr = self._check([("p", P32), ("d", D_TAG), ("s", P32),
                            ("9", list(int_to_data5(feats)))])
        assert addr.get_tag("9") == feats


# ================================================================ issue #5
class TestSettledPrepayGateIssue5:
    def test_settled_prepay_proceeds(self):
        from plugin.cln_lightning import CLNLightning, PrepayGate
        ln = CLNLightning.__new__(CLNLightning)
        main = HoldInvoice(payment_hash=(b"\x81" * 32).hex(), bolt11="x",
                           amount_msat=1000, expiry=300)
        main.attach_prepay_invoice(b"\x82" * 32)
        prepay = HoldInvoice(payment_hash=(b"\x82" * 32).hex(), bolt11="x",
                             amount_msat=10, expiry=300)
        prepay.funding_status = InvoiceState.SETTLED
        # PD-2: crash between prepay settle and main callback left the old
        # code `continue`-ing forever; SETTLED must read as redeemed.
        assert ln._bundle_prepay_state(main, prepay) is PrepayGate.PROCEED


# ================================================================ issue #6
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
    import threading
    ln._invoice_lock = threading.Lock()
    return ln


class TestCallbackLessHtlcIssue6:
    def _htlc(self, state=HtlcState.ACCEPTED, callback=None):
        return Htlc(state=state, short_channel_id="1x1x1", channel_id=1,
                    amount_msat=1000, created_at=int(time.time()),
                    request_callback=callback)

    def test_fail_without_callback_transitions_not_crashes(self):
        h = self._htlc()
        h.fail()  # must not raise
        assert h.state is HtlcState.CANCELLED

    def test_fail_timeout_without_callback_transitions_not_crashes(self):
        h = self._htlc()
        h.fail_timeout()
        assert h.state is HtlcState.CANCELLED

    def test_monitor_sweep_survives_poisoned_entry(self):
        # PD-3: one bad invoice must not starve the rest of the sweep
        ln = _ln()
        poisoned = HoldInvoice(payment_hash=(b"\x91" * 32).hex(), bolt11="x",
                               amount_msat=1000, expiry=300)
        poisoned.created_at = int(time.time()) - 301
        poisoned.incoming_htlcs = {self._htlc(callback=None)}
        healthy = HoldInvoice(payment_hash=(b"\x92" * 32).hex(), bolt11="x",
                              amount_msat=1000, expiry=300)
        healthy.created_at = int(time.time()) - 301
        ln._hold_invoices[poisoned.payment_hash.hex()] = poisoned
        ln._hold_invoices[healthy.payment_hash.hex()] = healthy
        ln._expire_pass({})  # one sweep — must process BOTH, not abort on #1
        assert poisoned.payment_hash.hex() not in ln._hold_invoices
        assert healthy.payment_hash.hex() not in ln._hold_invoices


# ================================================================ issue #7
class TestUnderfundGuardIssue7:
    def test_guard_applies_to_both_directions(self):
        src = (PLUGIN_DIR / "submarine_swaps.py").read_text()
        code = "\n".join(l for l in src.splitlines()
                         if not l.strip().startswith("#"))
        # electrum parity: skip applies to BOTH directions, not reverse-only
        assert not re.search(r"swap\.is_reverse\s+and\s+txin\.value_sats\(\)",
                             code), "guard still reverse-only"
        assert "txin.value_sats() < swap.onchain_amount" in code



