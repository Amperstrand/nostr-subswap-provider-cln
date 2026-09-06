"""Round 2 (owner-approved 2026-09-06) — persistence self-heal + settled
tombstone semantics + staged on-loop RPC. RED-first pins per item.

  R2-1a (Pers P1-1): tail-amputation recovery never heals the datastore
      key — every restart inside the recovery window silently drops the
      writes appended after recovery (empirically reproduced by the
      persistence audit lane). Contract: a successful amputation boot
      REWRITES the stored key clean (one forced consolidation).
  R2-1b (Pers P2-4): a datastore append whose response was lost
      re-appends the same patches → duplicated remove op →
      JsonPatchConflict at next boot with NO recovery (manual datastore
      surgery). Contract: per-patch sequential application salvages the
      longest valid prefix, quarantines the poison tail loudly, boots.
  R2-2 (Seams P1-3, owner option A): a settled hold's tombstone must
      carry the preimage and answer REPLAYED HTLCs with resolve — a
      restart inside lightningd's fulfill-commit window currently fails
      them (payer refunded after the client already claimed the escrow).
      Cancelled/expired tombstones keep failing (400F). Tombstones age
      out after the parked-HTLC CLTV horizon.
  R2-3 (Seams P1-5 staged): the claim path's synchronous lightningd
      RPCs run on the event loop — one busy RPC freezes claims, DM
      serving and monitoring alike (R3 self-inflicted). Stage 1: the
      park-gate listpays, the claim feerates and the claim-path
      datastore write go through to_thread + timeout.

Run: python3 -m pytest tests/test_round2_20260906.py -v
"""
import asyncio
import json
import sys
import time
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

import jsonpatch  # noqa: E402

from plugin.json_db import JsonDB  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402


def _logger():
    return SimpleNamespace(
        level="INFO",
        debug=lambda *a, **k: None, info=lambda *a, **k: None,
        warning=lambda *a, **k: None, error=lambda *a, **k: None)


class _FakeStorage:
    """CLNStorage stand-in: records writes/appends, serves reads."""

    def __init__(self, initial: str = ""):
        self.value = initial
        self.writes = []
        self.appends = []

    def read(self):
        return self.value

    def write(self, data: str) -> None:
        self.writes.append(data)
        self.value = data

    def append(self, data: str) -> None:
        self.appends.append(data)
        self.value = self.value + data

    def needs_consolidation(self) -> bool:
        return False

    def write_quarantine(self, fragment: str, label: str = "jsondb") -> str:
        return "quarantined-fake"


def _boot(storage) -> JsonDB:
    return JsonDB(s=storage.read(), storage=storage, logger=_logger())


# --------------------------------------------------------------- R2-1a
class TestAmputationSelfHeal:
    def test_recovery_boot_rewrites_stored_key_clean(self):
        base = '{"section_a": {"k": "v1"}}'
        # the #19 damage class: a truncated tail appended after the base
        damaged = base + ',\n{"section_b": {"broken'
        storage = _FakeStorage(damaged)
        db = _boot(storage)
        assert db.data.get("section_a") == {"k": "v1"}, "sanity: prefix loads"
        assert storage.writes, (
            "R2-1a: the amputation boot left the damaged tail in the "
            "datastore — every restart re-amputates and silently drops "
            "everything appended after recovery")
        assert "broken" not in storage.value, (
            "R2-1a: stored key still carries the damaged tail")

    def test_second_boot_loads_clean_without_amputation(self):
        base = '{"section_a": {"k": "v1"}}'
        damaged = base + ',\n{"section_b": {"broken'
        storage = _FakeStorage(damaged)
        db = _boot(storage)
        # a marker written after recovery (through the REAL write path)
        # must survive the next boot
        db.put("section_c", {"marker": True})
        db.write()
        db2 = _boot(storage)
        assert db2.data.get("section_c") == {"marker": True}, (
            "R2-1a: post-recovery writes were amputated on the next boot "
            "— the healing consolidation did not persist")

    def test_healthy_boot_does_not_consolidate(self):
        storage = _FakeStorage('{"section_a": {"k": "v1"}}')
        _boot(storage)
        assert storage.writes == [], (
            "R2-1a: healthy boots must keep the cheap append path — only "
            "recovery boots consolidate")


# --------------------------------------------------------------- R2-1b
class TestPatchApplyGuard:
    def test_duplicate_remove_patch_boots_and_salvages_prefix(self):
        # response-lost re-append: the SAME remove op twice (pending
        # changes are single op objects — the real append format)
        base = '{"swaps": {"a": 1, "b": 2}}'
        remove_a = {"op": "remove", "path": "/swaps/a"}
        add_c = {"op": "add", "path": "/swaps/c", "value": 3}
        storage = _FakeStorage(
            base + ',\n' + json.dumps(remove_a)
            + ',\n' + json.dumps(remove_a)
            + ',\n' + json.dumps(add_c))
        try:
            db = _boot(storage)
        except Exception as e:
            pytest.fail(
                f"R2-1b: duplicated patch crashed the boot unrecoverably: {e!r}")
        assert db.data["swaps"].get("b") == 2, (
            "R2-1b: valid prefix state was not salvaged")

    def test_fully_valid_patches_still_apply(self):
        base = '{"swaps": {"a": 1}}'
        replace_a = {"op": "replace", "path": "/swaps/a", "value": 2}
        storage = _FakeStorage(base + ',\n' + json.dumps(replace_a))
        db = _boot(storage)
        assert db.data["swaps"]["a"] == 2


# --------------------------------------------------------------- R2-2
def _d1_swap2() -> SwapData:
    swap = SwapData(
        is_reverse=False, locktime=2000, onchain_amount=21181,
        lightning_amount=20000, redeem_script="0020" + "ab" * 32,
        preimage="aa" * 32, prepay_hash=None, privkey=None,
        lockup_address="tb1qd1", receive_address="", funding_txid="f" * 64,
        spending_txid=None, is_redeemed=False)
    swap.claim_pubkey = "02" + "ab" * 31
    swap._payment_hash = ("dd" * 32)
    return swap


class _RecordingRequest:
    def __init__(self):
        self.results = []

    def set_result(self, value):
        if self.results:
            raise RuntimeError("second response")
        self.results.append(value)


def _cln_with_tombstone(tombstone_value):
    from plugin.cln_lightning import CLNLightning
    from plugin.invoices import HoldInvoice, InvoiceState
    db = MagicMock()
    tombstones = {}
    if tombstone_value is not None:
        tombstones["ab" * 32] = tombstone_value
    db.get_dict.side_effect = lambda k: (
        tombstones if k == "hold_tombstones" else {})
    db.write = MagicMock()
    plugin_instance = MagicMock()
    plugin_instance.plugin.rpc = MagicMock()
    plugin_instance.derive_secret = lambda label: b"\x11" * 32
    cln = CLNLightning(plugin_instance=plugin_instance,
                       config=SimpleNamespace(), db=db, logger=_logger())
    cln._tombstones = tombstones
    return cln


def _htlc_dict():
    return {"short_channel_id": "103x1x0", "id": 1,
            "amount_msat": 100000000,
            "cltv_expiry_relative": 144,
            "payment_hash": "ab" * 32}


class TestSettledTombstoneResolves:
    def test_settled_tombstone_resolves_replayed_htlc(self):
        preimage = bytes(range(32))
        cln = _cln_with_tombstone(
            {"preimage": preimage.hex(), "settled_at": int(time.time())})
        request = _RecordingRequest()
        cln.plugin_htlc_accepted_hook(
            {"payment_secret": "ab" * 32}, _htlc_dict(), request, None)
        assert request.results == [
            {"result": "resolve", "payment_key": preimage.hex()}], (
            "R2-2: a replayed HTLC for a SETTLED hold was failed — the "
            "payer gets refunded after the client already claimed")

    def test_cancelled_tombstone_still_fails(self):
        cln = _cln_with_tombstone(True)
        request = _RecordingRequest()
        cln.plugin_htlc_accepted_hook(
            {"payment_secret": "ab" * 32}, _htlc_dict(), request, None)
        assert request.results[0]["result"] == "fail", (
            "R2-2: cancelled/expired tombstones must keep failing")

    def test_finish_normal_swap_stamps_settled_tombstone(self):
        swap = _d1_swap2()
        sm = SwapManager.__new__(SwapManager)
        sm.logger = _logger()
        sm.db = MagicMock()
        sm.swaps = {swap._payment_hash: swap}
        from plugin.invoices import InvoiceState
        hold = MagicMock(name="hold")
        hold.funding_status = InvoiceState.SETTLED
        sm.lnworker = MagicMock()
        sm.lnworker.get_hold_invoice = MagicMock(return_value=hold)
        captured = {}

        def _delete(payment_hash, write_db=True, settled_preimage=None):
            captured["preimage"] = settled_preimage

        sm.lnworker.delete_hold_invoice = _delete
        sm.lnwatcher = MagicMock()
        sm._finish_normal_swap(swap)
        assert captured.get("preimage") == bytes.fromhex("aa" * 32), (
            "R2-2: the settle path must pass the preimage into the "
            "tombstone")

    def test_tombstones_age_out_past_cltv_horizon(self):
        from plugin.cln_lightning import CLNLightning as _CL
        TOMBSTONE_MAX_AGE_SEC = _CL.TOMBSTONE_MAX_AGE_SEC
        cln = _cln_with_tombstone(None)
        old = int(time.time()) - TOMBSTONE_MAX_AGE_SEC - 3600
        fresh = int(time.time())
        cln._tombstones.update({
            "01" * 32: {"preimage": "aa" * 32, "settled_at": old},
            "02" * 32: {"preimage": "bb" * 32, "settled_at": fresh},
            "03" * 32: True,
        })
        cln._prune_tombstones()
        assert "01" * 32 not in cln._tombstones, "expired tombstone kept"
        assert "02" * 32 in cln._tombstones, "fresh tombstone pruned"
        assert "03" * 32 in cln._tombstones


# --------------------------------------------------------------- R2-3
class TestStagedClaimPathRpcs:
    def test_park_gate_listpays_goes_through_thread(self):
        """R2-3 (source contract): _payment_parked_state must not run
        the blocking listpays on the event loop — asyncio.to_thread
        wrapper present in the park-gate path."""
        src = (Path(__file__).resolve().parent.parent
               / "swap-provider" / "plugin" / "submarine_swaps.py").read_text()
        import re
        assert re.search(r"asyncio\.to_thread\(\s*self\._payment_parked_state", src), (
            "R2-3: the park-gate listpays still runs synchronously on "
            "the event loop — a busy lightningd freezes all claims")

    def test_claim_fee_feerates_goes_through_thread(self):
        src = (Path(__file__).resolve().parent.parent
               / "swap-provider" / "plugin" / "submarine_swaps.py").read_text()
        assert "await asyncio.to_thread(self.get_claim_fee)" in src, (
            "R2-3: the claim-path feerates probe still runs "
            "synchronously on the event loop")


# --------------------------------------------------------------- R2-4
class TestHygieneBundle:
    def test_max_swap_amount_range_checked(self):
        from plugin.plugin_config import _validated_max_swap_amount
        with pytest.raises(ValueError):
            _validated_max_swap_amount("-5")
        with pytest.raises(ValueError):
            _validated_max_swap_amount("0")
        assert _validated_max_swap_amount("250000") == 250_000

    def test_prepayments_popped_on_d1_terminal_paths(self):
        src = (Path(__file__).resolve().parent.parent
               / "swap-provider" / "plugin" / "submarine_swaps.py").read_text()
        fn = src[src.index("def _finish_normal_swap"):]
        fn = fn[:fn.index("\n    def ", 10)]
        assert "self.prepayments.pop(swap.prepay_hash" in fn, (
            "R2-4a: _finish_normal_swap still leaks the prepay index")
        fn2 = src[src.index("def _fail_swap"):]
        fn2 = fn2[:fn2.index("\n    def ", 10)]
        assert "self.prepayments.pop(swap.prepay_hash" in fn2, (
            "R2-4a: _fail_swap still leaks the prepay index")

    def test_dm_replies_only_demux_owned_futures(self):
        src = (Path(__file__).resolve().parent.parent
               / "swap-provider" / "plugin" / "submarine_swaps.py").read_text()
        assert "content['reply_to'] in self.dm_replies" in src, (
            "R2-4c: any nostr key can grow dm_replies unboundedly with "
            "junk reply_to DMs — only futures we created may demux")

    def test_quarantine_prune_drops_only_stale_records(self):
        sm = SwapManager.__new__(SwapManager)
        sm.logger = _logger()
        sm.db = MagicMock()
        sm.quarantined_swaps = {
            "01" * 32: {"reason": "x", "swap": {"locktime": 100}},
            "02" * 32: {"reason": "x", "swap": {"locktime": 9_999_999}},
            "03" * 32: {"reason": "x", "swap": {}},  # no locktime: kept
        }
        sm._prune_quarantined_swaps(tip=5000)
        assert "01" * 32 not in sm.quarantined_swaps, (
            "R2-4b: stale quarantined record (plaintext secrets) kept forever")
        assert "02" * 32 in sm.quarantined_swaps
        assert "03" * 32 in sm.quarantined_swaps
        sm.db.write.assert_called_once()
