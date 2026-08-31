"""Unique-script-per-swap is a TRUSTLESS-MODEL requirement (see
lightning-playground docs/research/UNIQUE-SCRIPT-PER-SWAP.md):
preimage cross-satisfaction, watcher ambiguity, refund mis-binding,
linkability. Both creation paths must derive fresh material per swap —
never deterministic from client-visible inputs.

Live-verified on the jitlab 2026-08-24: two identical createnormalswap
bodies (same refund key, same amount) produced distinct address /
preimageHash / redeemScript every time. These tests pin it at the unit
level against regression to any deterministic derivation."""
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin import constants as _constants  # noqa: E402
_constants.net = _constants.BitcoinRegtest  # address encoding needs a net
from plugin.submarine_swaps import SwapManager  # noqa: E402


def _manager():
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.prepayments = {}
    import asyncio
    loop = asyncio.new_event_loop()
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.register_address = AsyncMock()
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1_000)
    sm.wallet.get_receiving_address = MagicMock(side_effect=lambda: f"addr-{os.urandom(4).hex()}")
    sm._add_or_reindex_swap = MagicMock()
    sm.add_lnwatcher_callback = MagicMock()
    sm._get_recv_amount = MagicMock(return_value=25_000)
    sm._get_send_amount = MagicMock(return_value=25_000)
    sm.get_min_amount = MagicMock(return_value=20_000)
    sm.get_max_amount = MagicMock(return_value=1_000_000)
    sm.lnworker = MagicMock()
    sm.lnworker.num_sats_can_send = MagicMock(return_value=10**9)
    sm.lnworker.register_hold_invoice_callback = MagicMock()
    sm.config = MagicMock()
    sm.config.network = _constants.BitcoinRegtest
    # #36: mock HSM deriver (deterministic per-label, like makesecret)
    import hmac, hashlib
    sm.set_hsm_deriver(lambda label: hmac.new(b'test-root', label.encode(), hashlib.sha256).digest())
    return sm


class TestUniqueScriptPerSwap:
    @pytest.mark.asyncio
    async def test_two_d2_creates_yield_distinct_material(self):
        sm = _manager()
        a = await sm.create_reverse_swap(lightning_amount_sat=25_000,
                                         their_pubkey=b"\x02" + b"\xab" * 32)
        b = await sm.create_reverse_swap(lightning_amount_sat=25_000,
                                         their_pubkey=b"\x02" + b"\xab" * 32)
        # #36: preimage is None in the record; derive via HSM to compare
        sm._get_swap_preimage(a) != sm._get_swap_preimage(b)
        assert sm._get_swap_privkey(a) != sm._get_swap_privkey(b)
        assert a.redeem_script != b.redeem_script
        assert a.lockup_address != b.lockup_address
        assert a.payment_hash != b.payment_hash

    @pytest.mark.asyncio
    async def test_source_has_no_deterministic_derivation(self):
        # #36 HSM-split: per-swap uniqueness now comes from the random
        # preimage_seed (os.urandom(16)) — the key material is HSM-derived
        # from the seed, so different seeds → different keys (same property
        # as the old os.urandom(32), but the secrets are never stored)
        src = (_plugin / "submarine_swaps.py").read_text()
        import re
        creates = re.findall(
            r"async def create_(?:reverse|normal)_swap.*?(?=\n    async def |\nclass )",
            src, re.S)
        assert creates, "creation functions not found"
        for fn in creates:
            if "create_reverse_swap" in fn:
                assert "os.urandom(16)" in fn, (
                    "d2 per-swap uniqueness must come from the random preimage seed")
            else:
                assert "os.urandom(32)" in fn, (
                    "d1 per-swap material must come from os.urandom")

    @pytest.mark.asyncio
    async def test_two_d1_creates_yield_distinct_material(self):
        """#81 §2 pending item: the d1 (create_normal_swap) path was the
        uncovered twin of test_two_d2_creates. Identical client inputs
        EXCEPT the client-minted hash (the wire contract supplies a
        fresh preimageHash per request) must still yield distinct
        script material via our fresh urandom key."""
        sm = _manager()
        sm.get_claim_fee = MagicMock(return_value=1_000)
        a, _, _ = await sm.create_normal_swap(
            lightning_amount_sat=25_000,
            payment_hash=b"\xaa" * 32,
            their_pubkey=b"\x02" + b"\xab" * 32)
        b, _, _ = await sm.create_normal_swap(
            lightning_amount_sat=25_000,
            payment_hash=b"\xbb" * 32,
            their_pubkey=b"\x02" + b"\xab" * 32)
        assert a.redeem_script != b.redeem_script
        assert a.lockup_address != b.lockup_address

    def test_payment_hash_freshness_domains(self):
        """#81 §1.4-3: a replayed preimageHash must be rejected from
        EVERY domain — live swap, known preimage, AND tombstoned hold
        (completed/expired d1 swaps de-index; their preimage is public
        in the claim witness)."""
        from plugin.submarine_swaps import RequestFieldError
        sm = _manager()
        sm.swaps = {}
        tombstones = set()

        def _fake_b11(**kw):
            inv = MagicMock()
            inv.bolt11 = "lntb" + os.urandom(4).hex()
            return inv

        sm.lnworker.b11invoice_from_hash = MagicMock(side_effect=_fake_b11)
        sm.lnworker.get_preimage = MagicMock(return_value=None)
        sm.lnworker.is_tombstoned = MagicMock(
            side_effect=lambda h: (h.hex() if isinstance(h, bytes) else h) in tombstones)
        sm.config.invoice_expiry_seconds = 300

        fresh = b"\x11" * 32
        sm._require_fresh_payment_hash(fresh)  # clean hash passes

        sm.swaps[fresh.hex()] = object()
        with pytest.raises(RequestFieldError, match='already in use'):
            sm._require_fresh_payment_hash(fresh)
        del sm.swaps[fresh.hex()]

        sm.lnworker.get_preimage = MagicMock(return_value=fresh.hex())
        with pytest.raises(RequestFieldError, match='already in use'):
            sm._require_fresh_payment_hash(fresh)
        sm.lnworker.get_preimage = MagicMock(return_value=None)

        tombstones.add(fresh.hex())
        with pytest.raises(RequestFieldError, match='tombstoned'):
            sm._require_fresh_payment_hash(fresh)

    @pytest.mark.asyncio
    async def test_completed_swap_hash_replay_rejected_end_to_end(self):
        """The live #81 §1.4-3 scenario: d1 swap created → hold removed +
        tombstoned + swap de-indexed (terminal transition) → the SAME
        preimageHash arrives in a new server_create_swap request.
        Pre-fix: both freshness domains were blind, the replay minted a
        second swap on a hash whose preimage is public onchain."""
        from plugin.submarine_swaps import RequestFieldError
        sm = _manager()
        sm.swaps = {}
        tombstones = {}

        def _fake_b11(**kw):
            inv = MagicMock()
            inv.bolt11 = "lntb" + os.urandom(4).hex()
            return inv

        sm.lnworker.b11invoice_from_hash = MagicMock(side_effect=_fake_b11)
        sm.lnworker.create_payment_info = MagicMock(side_effect=lambda **kw: os.urandom(32))
        sm.lnworker.bundle_payments = MagicMock()
        sm.lnworker.get_preimage = MagicMock(return_value=None)
        sm.lnworker.is_tombstoned = MagicMock(
            side_effect=lambda h: (h.hex() if isinstance(h, bytes) else h) in tombstones)
        sm.lnworker.num_sats_can_receive = MagicMock(return_value=10**9)
        sm.wallet.spendable_capacity_sat = MagicMock(return_value=10**9)
        sm.get_claim_fee = MagicMock(return_value=1_000)
        sm.config.invoice_expiry_seconds = 300

        req = {'invoiceAmount': 25_000,
               'preimageHash': (b"\xcc" * 32).hex(),
               'claimPublicKey': (b"\x02" + b"\xab" * 32).hex(),
               'type': 'reversesubmarine', 'pairId': 'BTC/BTC'}
        first = await sm.server_create_swap(dict(req))
        assert 'invoice' in first, first

        # terminal transition: hold tombstoned, swap de-indexed
        key = (b"\xcc" * 32).hex()
        sm.swaps.pop(key, None)
        tombstones[key] = True

        with pytest.raises(RequestFieldError, match='tombstoned'):
            await sm.server_create_swap(dict(req))
