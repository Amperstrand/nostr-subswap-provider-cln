"""Live-earned 2026-09-06 (deploy audit-r1 boot, cln-swap-mutinynet):
HSM-format swap records are quarantined at EVERY restart.

`_swap_integrity_errors` still required a plaintext `privkey` for BOTH
directions — the pre-#36/#43 contract. Since the HSM-split landed
(2026-08-31), new-format records store `privkey=null` + `claim_pubkey`
(d1, #43) / `preimage_seed`-derived keys with `claim_pubkey` (d2, #36),
and the use-time reader `_get_swap_privkey` accepts exactly that shape.
The load-time checker never caught up: 24+ live records quarantined
across boots on mutinynet (first `privkey missing/unparsable` at
quarantined_at 1788282573, one day after the HSM deploy), including two
at the audit-r1 boot itself (9716bf09…, e0fa1f7b… — both fresh d1 HSM
records with claim_pubkey set, funding not yet dispatched).

Blast radius of a wrongly-quarantined swap: popped from self.swaps, no
chain watcher, no hold-callback re-registration — a swap with
dispatched funding loses ALL automated recovery (refund/claim handling;
the HSM-derived keys keep it manually recoverable only).

Contract under test: key material for BOTH directions is
`privkey` (old format) OR `claim_pubkey` (HSM format) — mirroring
`_get_swap_privkey`'s acceptance rule — plus `redeem_script` always.

Run: python3 -m pytest tests/test_hsm_load_integrity.py -v
"""
import sys
from pathlib import Path

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.submarine_swaps import SwapData, SwapManager  # noqa: E402


def _hsm_d1_swap() -> SwapData:
    # the 9716bf09 production shape: d1, privkey null, claim_pubkey set
    swap = SwapData(
        is_reverse=False, locktime=3403408, onchain_amount=26227,
        lightning_amount=26362, redeem_script="0020" + "ab" * 32,
        preimage=None, prepay_hash="cd" * 32, privkey=None,
        lockup_address="tb1qd1", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap.claim_pubkey = "03c2d0cd15ea23f0f9570767a2d0bee3f5bc4b0b589bcad8a6d3d170d6cab993ed"
    swap.preimage_seed = None
    swap._payment_hash = "97" * 32
    return swap


def _hsm_d2_swap() -> SwapData:
    # the e0fa1f7b shape: d2 HSM, privkey null, claim_pubkey set,
    # preimage_seed set
    swap = SwapData(
        is_reverse=True, locktime=3403408, onchain_amount=21181,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage=None, prepay_hash=None, privkey=None,
        lockup_address="tb1qd2", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap.claim_pubkey = "02f30f8e7a283056042fcddf30f71e59076b3f863e406673e38b7f8e3838317151"
    swap.preimage_seed = "ef" * 32
    swap._payment_hash = "e0" * 32
    return swap


def _old_format_swap(privkey=b"\x01" * 32) -> SwapData:
    swap = SwapData(
        is_reverse=False, locktime=3403408, onchain_amount=21181,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage=None, prepay_hash=None, privkey=privkey,
        lockup_address="tb1qold", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = "01" * 32
    return swap


class TestHsmLoadIntegrity:
    def test_hsm_d1_record_is_not_quarantined(self):
        errors = SwapManager._swap_integrity_errors(_hsm_d1_swap()._payment_hash,
                                                    _hsm_d1_swap())
        assert errors == [], (
            "live bug 2026-09-06: HSM-format d1 records (privkey=null, "
            "claim_pubkey set — the #43 shape) are quarantined at every "
            "restart; the use-time reader accepts this exact shape")

    def test_hsm_d2_record_is_not_quarantined(self):
        errors = SwapManager._swap_integrity_errors(_hsm_d2_swap()._payment_hash,
                                                    _hsm_d2_swap())
        assert errors == [], (
            "live bug 2026-09-06: HSM-format d2 records are quarantined "
            "at every restart")

    def test_old_format_still_passes(self):
        errors = SwapManager._swap_integrity_errors(
            _old_format_swap()._payment_hash, _old_format_swap())
        assert errors == []

    def test_record_with_no_key_material_at_all_still_quarantines(self):
        swap = _old_format_swap(privkey=None)
        errors = SwapManager._swap_integrity_errors(swap._payment_hash, swap)
        assert any("privkey" in e for e in errors), (
            "a record with neither privkey nor claim_pubkey is genuinely "
            "keyless and MUST stay quarantined")

    def test_broken_redeem_script_still_quarantines(self):
        swap = _hsm_d1_swap()
        swap.redeem_script = None
        errors = SwapManager._swap_integrity_errors(swap._payment_hash, swap)
        assert any("redeem_script" in e for e in errors)
