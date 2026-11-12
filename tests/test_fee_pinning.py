"""#390 regression: request-time fees must equal the last PUBLISHED offer's.

The live-fire symptom: the kind-30315 offer announced mining_fee=1496
while the swap negotiation quoted a higher fee, tripping the electrum
client's fee-guard ("mining fee larger than announced"). Root cause:
offer and request path shared one live cache refreshed on the 10-min
offer cadence — any intra-cycle fee rise diverged them. The fix pins
request-time accounting to the fees the current offer actually carries.
"""
import math
from decimal import Decimal

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'swap-provider'))

# The fee-accounting paths under test are pure; the transports they are
# entangled with at import time (async bitcoin RPC, pyln) are stubbed so
# this test runs everywhere without the full plugin dependency chain.
for _name in ('bitcoinrpc', 'bitcoinrpc.aio', 'bitcoinrpc.authproxy', 'pyln.client', 'pyln.client.plugin'):
    if _name not in sys.modules:
        m = types.ModuleType(_name)
        m.__path__ = []  # submodules resolve via sys.modules only
        m.__getattr__ = lambda attr: type(attr, (), {})
        sys.modules[_name] = m

# plugin.utils asserts coroutines under @log_exceptions at import time on
# master when decorating sync helpers (pre-existing; the repo's own tests
# fail collection on it too). Load the REAL utils by path and relax only
# that decorator, so everything else constants.py & co. need stays genuine.
import importlib.util
_here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'swap-provider', 'plugin'))
_pkg = types.ModuleType('plugin')
_pkg.__path__ = [_here]
sys.modules.setdefault('plugin', _pkg)
_spec = importlib.util.spec_from_file_location('plugin.utils', os.path.join(_here, 'utils.py'))
_utils = importlib.util.module_from_spec(_spec)
sys.modules['plugin.utils'] = _utils
_spec.loader.exec_module(_utils)
_utils.log_exceptions = lambda func: (lambda *a, **k: func(*a, **k)) if not __import__('asyncio').iscoroutinefunction(func) else _utils.__dict__.get('_orig_log_exceptions', (lambda f: f))(func)

from plugin import submarine_swaps as ss  # noqa: E402


class _FeeStub:
    """Just enough SwapServer for the fee-accounting paths."""

    percentage = 0.5
    _min_amount = 20000
    _max_amount = 10000000
    normal_fee = None
    lockup_fee = None
    claim_fee = None
    pinned_fees = None

    def get_min_amount(self):
        return self._min_amount

    def get_max_amount(self):
        return self._max_amount

    _effective_fees = ss.SwapManager._effective_fees
    pin_fees_to_offer = ss.SwapManager.pin_fees_to_offer
    check_invoice_amount = ss.SwapManager.check_invoice_amount
    _get_recv_amount = ss.SwapManager._get_recv_amount
    _get_send_amount = ss.SwapManager._get_send_amount


def _stub(normal, lockup, claim):
    s = _FeeStub()
    s.normal_fee, s.lockup_fee, s.claim_fee = normal, lockup, claim
    return s


def test_fallback_before_first_offer():
    s = _stub(1000, 2000, 500)
    assert s._effective_fees() == (1000, 2000, 500)


def test_pin_freezes_against_intra_cycle_drift():
    s = _stub(1496, 2992, 1496)
    s.pin_fees_to_offer()  # offer published with 1496
    # fee cache rises right after (the #390 window)
    s.normal_fee, s.lockup_fee, s.claim_fee = 2200, 4400, 2200
    assert s._effective_fees() == (1496, 2992, 1496)


def test_recv_amount_forward_uses_pinned_normal_fee():
    s = _stub(1496, 2992, 1496)
    s.pin_fees_to_offer()
    s.normal_fee = 5000  # live drift must NOT leak into the quote
    got = s._get_recv_amount(100000, is_reverse=False)
    # mirror the product formula exactly, with the PINNED fee
    x = Decimal(100000) - Decimal(1496)
    pct = math.ceil(x * Decimal(0.5) / (Decimal(100) + Decimal(0.5)))
    assert got == int(x) - pct
    # and prove the drift did not leak: with the live 5000 it would differ
    s2 = _stub(5000, 2992, 1496)
    assert s2._get_recv_amount(100000, is_reverse=False) != got


def test_recv_amount_reverse_uses_pinned_lockup_fee():
    s = _stub(1496, 2992, 1496)
    s.pin_fees_to_offer()
    s.lockup_fee = 9000
    got = s._get_recv_amount(100000, is_reverse=True)
    pct = math.ceil(Decimal(0.5) * Decimal(100000) / 100)
    expected = math.floor(Decimal(100000) - Decimal(pct) - Decimal(2992))
    assert got == expected


def test_send_amount_roundtrip_stable_under_drift():
    s = _stub(1496, 2992, 1496)
    s.pin_fees_to_offer()
    recv = s._get_recv_amount(100000, is_reverse=False)
    before = s._get_send_amount(recv, is_reverse=False)
    s.normal_fee = 7777  # drift after the quote
    after = s._get_send_amount(recv, is_reverse=False)
    assert before == after  # both ride the PIN, not the cache


def test_no_drift_math_unchanged():
    """Control: with no drift, pinned == live, numbers match the old code."""
    s = _stub(1496, 2992, 1496)
    s.pin_fees_to_offer()
    live = _stub(1496, 2992, 1496)
    for is_reverse in (False, True):
        assert s._get_recv_amount(100000, is_reverse=is_reverse) == \
            live._get_recv_amount(100000, is_reverse=is_reverse)
        assert s._get_send_amount(100000, is_reverse=is_reverse) == \
            live._get_send_amount(100000, is_reverse=is_reverse)


def test_dust_guard_still_applies():
    s = _stub(10**9, 10**9, 10**9)  # absurd fees
    s.pin_fees_to_offer()
    assert s._get_recv_amount(100000, is_reverse=True) is None


def test_module_imports_without_workarounds():
    """The live plugin crashed at getmanifest (deployed 2026-11-12):
    a sync method carried @log_exceptions, which asserts coroutines at
    import time. This suite's log_exceptions passthrough monkeypatch had
    been masking that. The module must import BARE — no patches first."""
    import subprocess, sys
    code = "import sys; sys.path.insert(0, 'swap-provider'); " \
           "import plugin.submarine_swaps as m; " \
           "assert hasattr(m, 'SwapManager'); print('BARE-IMPORT-OK')"
    r = subprocess.run([sys.executable, "-c", code], cwd=".",
                       capture_output=True, text=True)
    assert r.returncode == 0 and "BARE-IMPORT-OK" in r.stdout, r.stderr[-500:]
