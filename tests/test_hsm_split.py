"""Regression tests for issue #36: HSM-split of claim secrets.

Contract: new-format swaps store only public data + a derivation seed
in the datastore. Secrets (claim privkey, preimage) are derived from
CLN's HSM at use-time via makesecret. Old-format swaps keep their
plaintext secrets until expiry.

Run: python3 -m pytest tests/test_hsm_split.py -v
"""
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from hashlib import sha256

import sys
import types
PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

from plugin.submarine_swaps import SwapData, SwapManager
from electrum_ecc import ECPrivkey


def _hsm_deriver(label: str) -> bytes:
    """Deterministic mock HSM: same derivation math as CLN's makesecret
    (HKDF-SHA256), using a fixed root for reproducibility."""
    import hmac, hashlib
    root = b'\x11' * 32  # test root — NOT a real hsm_secret
    return hmac.new(root, label.encode(), hashlib.sha256).digest()


def _swap(**kwargs):
    """Minimal SwapData for testing."""
    defaults = dict(
        is_reverse=True, locktime=319900, onchain_amount=20238,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage=None, prepay_hash=None, privkey=None,
        preimage_seed=None, claim_pubkey=None,
        lockup_address="bcrt1qfake", receive_address="bcrt1qfake2",
        funding_txid=None, spending_txid=None, is_redeemed=False,
    )
    defaults.update(kwargs)
    return SwapData(**defaults)


def _sm():
    """Minimal SwapManager with the HSM deriver wired."""
    sm = object.__new__(SwapManager)
    sm.set_hsm_deriver(_hsm_deriver)
    return sm


class TestSwapDataFields:
    def test_new_format_has_no_plaintext_secrets(self):
        """Post-HSM-split SwapData: privkey and preimage are None; seed
        and pubkey are set (safe to store)."""
        seed = os.urandom(16)
        s = _swap(preimage_seed=seed.hex(), claim_pubkey="03abc")
        assert s.privkey is None, "new-format swap must not carry a plaintext privkey"
        assert s.preimage is None, "new-format swap must not carry a plaintext preimage"
        assert s.preimage_seed == seed.hex()
        assert s.claim_pubkey == "03abc"

    def test_old_format_still_carries_secrets(self):
        """Old-format SwapData: privkey and preimage are set (backward compat)."""
        s = _swap(privkey="ab" * 32, preimage="cd" * 32)
        assert s.privkey == "ab" * 32
        assert s.preimage == "cd" * 32
        assert s.preimage_seed is None
        assert s.claim_pubkey is None

    def test_json_serialization_excludes_none_secrets(self):
        """The JSON blob for a new-format swap contains no privkey/preimage."""
        seed = os.urandom(16)
        s = _swap(preimage_seed=seed.hex(), claim_pubkey="03abc")
        serialized = json.dumps({"privkey": s.privkey, "preimage": s.preimage,
                                 "preimage_seed": s.preimage_seed,
                                 "claim_pubkey": s.claim_pubkey})
        assert '"privkey": null' in serialized or '"privkey":null' in serialized
        assert '"preimage": null' in serialized or '"preimage":null' in serialized
        assert seed.hex() in serialized  # seed IS stored
        assert "03abc" in serialized  # pubkey IS stored


class TestHsmDerivation:
    def test_get_swap_privkey_derives_from_hsm(self):
        """New-format swap: _get_swap_privkey calls the HSM deriver AND
        the derived key must match the script's claim_pubkey (the C4
        binding — a fixture carrying an inconsistent pubkey is now
        refused, so pin the consistent one)."""
        sm = _sm()
        payment_hash = sha256(b"test").hexdigest()
        consistent_pub = ECPrivkey(
            _hsm_deriver(f"swap-claim-{payment_hash}")).get_public_key_bytes(
                compressed=True).hex()
        s = _swap(preimage_seed="aa" * 16, claim_pubkey=consistent_pub)
        s._payment_hash = payment_hash
        key = sm._get_swap_privkey(s)
        assert len(key) == 32
        assert key == _hsm_deriver(f"swap-claim-{payment_hash}")

    def test_get_swap_privkey_uses_stored_for_old_format(self):
        """Old-format swap: _get_swap_privkey returns the stored key."""
        sm = _sm()
        s = _swap(privkey="ab" * 32)
        key = sm._get_swap_privkey(s)
        assert key == bytes.fromhex("ab" * 32)

    def test_get_swap_preimage_derives_from_hsm(self):
        """New-format swap: _get_swap_preimage derives from the seed."""
        sm = _sm()
        seed_hex = "ab" * 16
        s = _swap(preimage_seed=seed_hex)
        preimage = sm._get_swap_preimage(s)
        assert len(preimage) == 32
        assert preimage == _hsm_deriver(f"swap-preimage-{seed_hex}")

    def test_get_swap_preimage_uses_stored_for_old_format(self):
        """Old-format swap: _get_swap_preimage returns the stored preimage."""
        sm = _sm()
        s = _swap(preimage="cd" * 32)
        preimage = sm._get_swap_preimage(s)
        assert preimage == bytes.fromhex("cd" * 32)

    def test_derivation_is_deterministic(self):
        """Same seed + same HSM → same preimage, every time."""
        sm = _sm()
        seed_hex = "12" * 16
        s = _swap(preimage_seed=seed_hex)
        p1 = sm._get_swap_preimage(s)
        p2 = sm._get_swap_preimage(s)
        assert p1 == p2

    def test_payment_hash_matches_derived_preimage(self):
        """The chicken-and-egg chain: seed → preimage → sha256 → payment_hash."""
        sm = _sm()
        seed = os.urandom(16)
        preimage = sm._derive_secret(f"swap-preimage-{seed.hex()}")
        payment_hash = sha256(preimage).hexdigest()
        # re-derivation gives the same preimage → same hash
        preimage2 = sm._derive_secret(f"swap-preimage-{seed.hex()}")
        assert sha256(preimage2).hexdigest() == payment_hash

    def test_bytes_claim_pubkey_normalized_and_patch_serializable(self):
        """Production crash 2026-08-31 (contracts-r1): create_reverse_swap
        passed claim_pubkey as raw BYTES into SwapData; to_json() left them
        bytes; JsonDB.add_patch's json.dumps crashed (under pyln's patched
        JSONEncoder.default the TypeError is the confusing
        'JSONEncoder.default() missing 1 required positional argument').
        Every onchain_to_ln createswap failed 'internal error serving
        createnormalswap' on both cln providers. Contract: the claim_pubkey
        FIELD is always a 66-hex string, so every datastore patch is
        natively JSON-serializable. Unit tests missed this because detached
        SwapData objects (no live JsonDB) never fire add_patch."""
        from plugin.json_db import JsonDB
        db = JsonDB(s='{}', storage=MagicMock(), logger=MagicMock())
        # exactly what create_reverse_swap passed at the crash site
        swap = _swap(claim_pubkey=b'\x02' + b'\xab' * 32)
        assert swap.claim_pubkey == '02' + 'ab' * 32, \
            'converter must normalize bytes to hex at construction'
        db.data['submarine_swaps'] = {}
        db.data['submarine_swaps']['aa' * 32] = swap  # fires add_patch
        assert db.pending_changes, 'storing a swap must produce a datastore patch'
        for p in db.pending_changes:
            json.loads(p)  # pre-fix: TypeError serializing raw bytes

    def test_missing_hsm_deriver_raises(self):
        """Calling _derive_secret without set_hsm_deriver is a loud failure."""
        sm = object.__new__(SwapManager)
        try:
            sm._derive_secret("test")
            assert False, "should have raised"
        except RuntimeError:
            pass

    def test_no_privkey_and_no_pubkey_raises(self):
        """A swap with neither privkey nor claim_pubkey is malformed."""
        sm = _sm()
        s = _swap()  # both None
        s._payment_hash = "ff" * 32
        try:
            sm._get_swap_privkey(s)
            assert False, "should have raised"
        except RuntimeError:
            pass


class TestDatastoreCleanliness:
    def test_new_swap_record_has_no_secrets(self):
        """Simulated datastore entry for a new-format swap."""
        record = {
            "is_reverse": True,
            "locktime": 319900,
            "onchain_amount": 20238,
            "lightning_amount": 20000,
            "redeem_script": "0020abcd",
            "lockup_address": "bcrt1qfake",
            "preimage": None,
            "privkey": None,
            "preimage_seed": "ab" * 16,
            "claim_pubkey": "03abc",
        }
        serialized = json.dumps(record)
        # The seed and pubkey are safe to store
        assert record["preimage_seed"] in serialized
        assert record["claim_pubkey"] in serialized
        # The secrets must be None, not hex strings
        assert record["preimage"] is None
        assert record["privkey"] is None
        # Verify no actual secret material is present (beyond field names)
        import re
        # Remove the field names themselves; check no hex values remain
        # where secrets would be
        cleaned = serialized.replace('"preimage": null', '').replace('"privkey": null', '')
        # The seed is present but is NOT a secret (useless without HSM)
        assert 'ab' * 16 in cleaned  # seed is there
        # No 64-char hex strings that could be privkeys
        hex64 = re.findall(r'"[0-9a-f]{64}"', cleaned)
        assert len(hex64) == 0, f"found potential secrets: {hex64}"


class TestD1HsmSplit:
    """#43: the d1 path (create_normal_swap) still persisted the server
    refund privkey in plaintext (os.urandom → privkey=hex). Live
    evidence 2026-08-31: two same-day d1 records carried privkey=SET.
    Contract: a new d1 record stores NO plaintext privkey — the key is
    HSM-derived from the swap-claim-{payment_hash} label (the label is
    client-influenceable but _derive_secret is HSM-bound; duplicate
    hashes are rejected by _require_fresh_payment_hash), the record
    carries only claim_pubkey, and the existing reader re-derives the
    SAME key (writer-reader invariant)."""

    def _d1_manager(self):
        import asyncio  # noqa: F401  (kept for the runner below)
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from plugin.json_db import JsonDB
        from plugin.constants import BitcoinRegtest
        sm = SwapManager.__new__(SwapManager)
        sm.set_hsm_deriver(_hsm_deriver)
        sm.logger = MagicMock()
        sm.db = JsonDB(s='{}', storage=MagicMock(), logger=MagicMock())
        sm.db.data['submarine_swaps'] = {}
        sm.swaps = sm.db.data['submarine_swaps']
        sm._swaps_by_funding_outpoint = {}
        sm._swaps_by_lockup_address = {}
        sm.wallet = MagicMock()
        sm.wallet.get_local_height = AsyncMock(return_value=320000)
        sm.wallet.get_receiving_address = MagicMock(return_value='bcrt1qfake')
        sm._get_recv_amount = MagicMock(return_value=19700)
        sm.config = SimpleNamespace(network=BitcoinRegtest())
        sm.lnworker = MagicMock()
        sm.lnworker.b11invoice_from_hash = MagicMock(
            return_value=types.SimpleNamespace(bolt11='lntbs1fake'))
        sm.lnworker.create_payment_info = MagicMock(return_value=b'\xbb' * 32)
        sm.lnworker.get_preimage = MagicMock(return_value=None)
        sm.prepayments = {}
        sm.get_claim_fee = MagicMock(return_value=37)
        sm.lnwatcher = MagicMock()
        sm.lnwatcher.register_address = AsyncMock(return_value=None)
        sm.add_lnwatcher_callback = MagicMock()
        return sm

    def test_d1_record_clean_and_reader_rederives(self):
        import asyncio
        from electrum_ecc import ECPrivkey
        sm = self._d1_manager()
        swap, _invoice, _prepay = asyncio.run(sm.create_normal_swap(
            lightning_amount_sat=20000, payment_hash=b'\xaa' * 32,
            their_pubkey=b'\x02' + b'\x03' * 31, requester_npub=None))
        record = sm.swaps['aa' * 32]
        assert record.is_reverse is False
        assert record.privkey is None, \
            'd1 record must not persist the refund privkey in plaintext (#43)'
        expected = ECPrivkey(
            _hsm_deriver(f"swap-claim-{'aa' * 32}")
        ).get_public_key_bytes(compressed=True)
        assert record.claim_pubkey == expected.hex(), \
            'writer must derive the refund key from the HSM label'
        assert expected.hex() in record.redeem_script, \
            'the lockup script must bind the derived key'
        reread = ECPrivkey(sm._get_swap_privkey(record)
                           ).get_public_key_bytes(compressed=True)
        assert reread == expected, \
            'reader must re-derive the SAME key the writer used'
        for p in sm.db.pending_changes:
            json.loads(p)
