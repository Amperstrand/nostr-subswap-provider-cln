"""Load-integrity (audit round 6): issue #19 refuse-loudly datastore
tail-amputation (ERROR + quarantine .frag + prefix recovery, F05), issue
#18 no silent startup deletion of forward swaps without hold invoice
(F04), issue #22/F21 missing-key-material quarantine at load, the cheap
load-consistency scan (orphans WARN, INFO counts) and the r6 health
fields.

Key-material hygiene: nothing in these tests logs or asserts on actual
key BYTES — the JsonDB fragments under test are synthetic; the masking
rule (length + sha256 whenever a marker like privkey appears) is itself
asserted.

Run: python3 -m pytest tests/test_load_integrity.py -v
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
from types import SimpleNamespace

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

import plugin.submarine_swaps  # noqa: F401,E402  (registers SwapData)
from plugin import submarine_swaps as ss  # noqa: E402
from plugin.cln_logger import PluginLogger  # noqa: E402
from plugin.cln_storage import CLNStorage, StorageReadWriteError  # noqa: E402
from plugin.json_db import JsonDB  # noqa: E402
from plugin.submarine_swaps import SwapData, SwapManager  # noqa: E402
from plugin.health import build_report  # noqa: E402
from plugin import constants as constants_mod  # noqa: E402

constants_mod.net = constants_mod.BitcoinRegtest()


class Sink:
    """CLN plugin.log-compatible recorder (valcommon pattern)."""
    def __init__(self):
        self.messages = []

    def __call__(self, msg, level="info"):
        self.messages.append(msg)

    def joined(self):
        return "\n".join(self.messages)


def make_logger(sink, level="DEBUG"):
    return PluginLogger("load-integrity", sink, level=level)


class MemStorage:
    """JsonDB storage stub: append-style, records everything."""
    def __init__(self):
        self.appends = []
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def append(self, data):
        self.appends.append(data)

    def needs_consolidation(self):
        return False


def _swap_rec(payment_hash_hex, *, is_reverse=True, privkey="01" * 32,
              preimage=None, redeem_script="51" * 10, locktime=5000,
              is_redeemed=False, lockup_address="tb1qfake", **extra):
    rec = {
        "is_reverse": is_reverse, "locktime": locktime,
        "onchain_amount": 21181, "lightning_amount": 20000,
        "redeem_script": redeem_script, "preimage": preimage,
        "prepay_hash": None, "privkey": privkey,
        "lockup_address": lockup_address, "receive_address": "",
        "funding_txid": None, "spending_txid": None,
        "is_redeemed": is_redeemed, "registered": False,
    }
    rec.update(extra)
    return rec


def _db_payload(swaps=None, **sections):
    data = {"submarine_swaps": swaps or {}}
    data.update(sections)
    return json.dumps(data, indent=4, sort_keys=True)


def _make_sm(payload, sink, lnworker=None):
    """The REAL SwapManager startup path over a REAL JsonDB."""
    storage = MemStorage()
    db = JsonDB(s=payload, storage=storage, logger=make_logger(sink))
    if lnworker is None:
        lnworker = MagicMock()
        lnworker.get_hold_invoice = MagicMock(return_value=None)
        lnworker.register_hold_invoice_callback = MagicMock()
    # mirror CLNLightning.__init__: payment dicts come from the same db
    lnworker._invoices = db.get_dict("invoices")
    lnworker._preimages = db.get_dict("lightning_preimages")
    sm = SwapManager.__new__(SwapManager)
    SwapManager.__init__(
        sm, wallet=MagicMock(), lnworker=lnworker, db=db,
        plugin_config=SimpleNamespace(sweep_grace_blocks=288),
        logger=make_logger(sink), chain_monitor=MagicMock())
    sm._test_storage = storage
    sm._test_db = db
    sm._test_lnworker = lnworker
    return sm


# ---------------------------------------------------------------------------
# #19 / F05 — refuse-loudly tail amputation
# ---------------------------------------------------------------------------

class TestTailAmputation:
    def _fragmenting_datastore(self, tmpdir):
        """REAL CLNStorage over a file-backed fake datastore RPC that
        maps the quarantine child keys to sibling .frag files (valP
        FileDatastore pattern)."""
        path = os.path.join(tmpdir, "jsondb")

        class DS:
            generation = 0

            def listdatastore(self, *, key):
                content = ""
                if os.path.exists(path):
                    with open(path) as f:
                        content = f.read()
                return {"datastore": [{"key": ["swap-provider", "jsondb"],
                                       "generation": self.generation,
                                       "string": content}]}

            def datastore(self, *, key, string, mode):
                if key == ["swap-provider", "jsondb"]:
                    dest = path
                else:
                    assert key[0] == "swap-provider" and key[1].endswith(".frag")
                    dest = os.path.join(tmpdir, key[1])
                with open(dest, "w") as f:
                    f.write(string)
                self.generation += 1
                return {"key": list(key), "generation": self.generation}

        return DS()

    def _load(self, ds, sink):
        logger = make_logger(sink)
        storage = CLNStorage(db_string_writer=ds.datastore,
                             db_string_reader=ds.listdatastore,
                             logger=logger)
        db = JsonDB(s=storage.read(), storage=storage, logger=logger)
        return db

    def test_truncated_file_errors_quarantines_and_loads_prefix(self, tmp_path):
        sink = Sink()
        ds = self._fragmenting_datastore(str(tmp_path))
        good = _db_payload({"aa" * 32: _swap_rec("aa" * 32)})
        with open(os.path.join(str(tmp_path), "jsondb"), "w") as f:
            f.write(good)
        # non-pristine damage: an appended record chopped mid-way
        with open(os.path.join(str(tmp_path), "jsondb"), "a") as f:
            f.write(',\n{"submarine_swaps": {"bb' + "32: " + '"x" * 5')

        db = self._load(ds, sink)

        errs = [m for m in sink.messages if m.startswith("ERROR")]
        assert any("datastore damage" in m and "discarding unparsable final"
                   in m for m in errs), sink.joined()
        dmg = next(m for m in errs if "datastore damage" in m)
        assert f"len=" in dmg and "sha256=" in dmg
        # the appended fragment names a swap section — it may carry key
        # material, so no hex preview may appear
        assert "first64=" not in dmg
        frags = [p for p in os.listdir(str(tmp_path)) if p.endswith(".frag")]
        assert len(frags) == 1, os.listdir(str(tmp_path))
        with open(os.path.join(str(tmp_path), frags[0])) as f:
            preserved = f.read()
        assert preserved.startswith(",")  # separator + unparsable tail
        # prefix recovery: the intact record still loads as SwapData
        loaded = db.data.get("submarine_swaps", {})
        assert "aa" * 32 in loaded
        assert isinstance(loaded["aa" * 32], SwapData)

    def test_structural_fragment_gets_hex_preview(self, tmp_path):
        sink = Sink()
        ds = self._fragmenting_datastore(str(tmp_path))
        with open(os.path.join(str(tmp_path), "jsondb"), "w") as f:
            f.write(_db_payload({}))
        # structural junk tail: no key-material markers anywhere
        with open(os.path.join(str(tmp_path), "jsondb"), "a") as f:
            f.write(',\n{"junk_section": {"alpha')

        self._load(ds, sink)

        dmg = next(m for m in sink.messages
                   if m.startswith("ERROR") and "datastore damage" in m)
        assert "first64=" in dmg and "last64=" in dmg  # structural: hex ok
        assert "withheld" not in dmg
        tail = '{"junk_section": {"alpha'
        frag = tail.encode()
        want = hashlib.sha256((",\n" + tail).encode()).hexdigest()
        assert want in dmg
        assert frag[:64].hex() in dmg and frag[-64:].hex() in dmg

    def test_pristine_file_logs_nothing_loud(self, tmp_path):
        sink = Sink()
        ds = self._fragmenting_datastore(str(tmp_path))
        with open(os.path.join(str(tmp_path), "jsondb"), "w") as f:
            f.write(_db_payload({"aa" * 32: _swap_rec("aa" * 32)}))

        db = self._load(ds, sink)

        assert not [m for m in sink.messages if m.startswith("ERROR")]
        assert not [p for p in os.listdir(str(tmp_path)) if p.endswith(".frag")]
        assert "aa" * 32 in db.data.get("submarine_swaps", {})

    def test_quarantine_write_failure_is_loud_but_loads(self, tmp_path):
        sink = Sink()
        ds = self._fragmenting_datastore(str(tmp_path))
        with open(os.path.join(str(tmp_path), "jsondb"), "w") as f:
            f.write(_db_payload({}))
            f.write(',\n{"submarine_swaps": {"zz')

        def exploding_writer(**kw):
            raise RuntimeError("datastore down")

        ds.datastore = exploding_writer
        logger = make_logger(sink)
        storage = CLNStorage(db_string_writer=exploding_writer,
                             db_string_reader=ds.listdatastore,
                             logger=logger)
        db = JsonDB(s=storage.read(), storage=storage, logger=logger)
        errs = [m for m in sink.messages if m.startswith("ERROR")]
        assert any("datastore damage" in m for m in errs)
        assert any("NOT preserved" in m or "failed to preserve" in m
                   for m in errs), sink.joined()
        assert isinstance(db.data, dict)  # prefix still recovered

    def test_compact_dump_truncation_is_loud_not_assert(self):
        """A truncation inside a CONSOLIDATED compact dump (no ',\n'
        boundaries) is not amputatable — it must route to the loud
        WalletFileException, never a bare AssertionError crash."""
        from plugin.utils import WalletFileException
        sink = Sink()
        compact = json.dumps({"submarine_swaps":
                              {"aa" * 32: _swap_rec("aa" * 32)}},
                             sort_keys=True)
        truncated = compact[:-40]  # mid-record: unbalanced, no boundary
        with pytest.raises(WalletFileException):
            JsonDB(s=truncated, storage=MemStorage(),
                   logger=make_logger(sink))


# ---------------------------------------------------------------------------
# #18 / F04 — no silent startup deletion
# ---------------------------------------------------------------------------

class TestStartupHoldInvoiceQuarantine:
    def test_missing_hold_quarantines_not_deletes(self):
        sink = Sink()
        ph = "cc" * 32
        sm = _make_sm(_db_payload({ph: _swap_rec(ph, is_reverse=False)}), sink)

        assert ph not in sm.swaps                     # not processed
        assert ph in sm.quarantined_swaps             # but PRESERVED
        entry = sm.quarantined_swaps[ph]
        assert "hold invoice missing" in entry["reason"]
        assert entry["swap"]["privkey"] == "01" * 32  # full record kept
        errs = [m for m in sink.messages if m.startswith("ERROR")]
        assert any("quarantined swap" in m and ph in m
                   and "hold invoice missing" in m for m in errs)
        assert sm._test_storage.writes, "quarantine must be persisted"
        assert not sm._swaps_by_lockup_address          # never indexed
        assert not sm._test_lnworker.register_hold_invoice_callback.called

    def test_hold_present_registers_normally(self):
        sink = Sink()
        ph = "cc" * 32
        lnworker = MagicMock()
        lnworker.get_hold_invoice = MagicMock(return_value=object())
        lnworker.register_hold_invoice_callback = MagicMock()
        sm = _make_sm(_db_payload({ph: _swap_rec(ph, is_reverse=False)}),
                      sink, lnworker=lnworker)

        assert ph in sm.swaps
        assert ph not in sm.quarantined_swaps
        assert lnworker.register_hold_invoice_callback.called
        assert not [m for m in sink.messages if m.startswith("ERROR")]

    def test_redeemed_forward_without_hold_is_kept(self):
        sink = Sink()
        ph = "cc" * 32
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, is_reverse=False, is_redeemed=True)}), sink)

        assert ph in sm.swaps  # the old pop only hit unredeemed forwards
        assert ph not in sm.quarantined_swaps

    def test_reverse_swap_never_needs_a_hold(self):
        sink = Sink()
        ph = "dd" * 32
        sm = _make_sm(_db_payload({ph: _swap_rec(ph, is_reverse=True)}), sink)

        assert ph in sm.swaps
        assert ph not in sm.quarantined_swaps


# ---------------------------------------------------------------------------
# #22 / F21 — missing-key-material quarantine at load
# ---------------------------------------------------------------------------

class TestKeyMaterialIntegrity:
    def test_missing_privkey_quarantines(self):
        sink = Sink()
        ph = "ee" * 32
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, privkey="")}), sink)

        assert ph not in sm.swaps
        reason = sm.quarantined_swaps[ph]["reason"]
        assert "privkey missing/unparsable" in reason
        errs = [m for m in sink.messages if m.startswith("ERROR")]
        assert any("quarantined swap" in m and ph in m for m in errs)

    def test_short_privkey_quarantines(self):
        sink = Sink()
        ph = "ee" * 32
        sm = _make_sm(_db_payload({ph: _swap_rec(ph, privkey="01" * 31)}), sink)
        assert "privkey missing/unparsable" in sm.quarantined_swaps[ph]["reason"]

    def test_missing_redeem_script_quarantines(self):
        sink = Sink()
        ph = "ee" * 32
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, redeem_script=None)}), sink)
        assert "redeem_script missing/unparsable" in sm.quarantined_swaps[ph]["reason"]

    def test_nonhex_redeem_script_quarantines(self):
        sink = Sink()
        ph = "ee" * 32
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, redeem_script="zznothex")}), sink)
        assert "redeem_script missing/unparsable" in sm.quarantined_swaps[ph]["reason"]

    def test_preimage_hash_mismatch_quarantines(self):
        sink = Sink()
        ph = "ee" * 32
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, preimage="a1" * 32)}), sink)  # sha256(a1..) != ee..
        assert "preimage does not hash to payment_hash" \
            in sm.quarantined_swaps[ph]["reason"]

    def test_preimage_hash_match_is_kept(self):
        sink = Sink()
        ph = "ee" * 32
        preimage = bytes.fromhex("a1" * 32)
        ph = hashlib.sha256(preimage).hexdigest()
        sm = _make_sm(_db_payload(
            {ph: _swap_rec(ph, preimage=preimage.hex())}), sink)
        assert ph in sm.swaps and ph not in sm.quarantined_swaps

    def test_corrupt_payment_hash_key_quarantines_not_crashes(self):
        sink = Sink()
        bad_key = "nothex"
        sm = _make_sm(_db_payload({bad_key: _swap_rec(bad_key)}), sink)
        assert "payment_hash key is not valid 32-byte hex" \
            in sm.quarantined_swaps[bad_key]["reason"]

    def test_valid_records_pass_cleanly(self):
        sink = Sink()
        ph = "ff" * 32
        sm = _make_sm(_db_payload({ph: _swap_rec(ph)}), sink)
        assert ph in sm.swaps
        assert not sm.quarantined_swaps
        assert not [m for m in sink.messages if m.startswith("ERROR")]


# ---------------------------------------------------------------------------
# load-consistency scan + health surface (r6)
# ---------------------------------------------------------------------------

class TestLoadIntegrityScan:
    def test_orphans_warn_not_delete_and_counts_logged(self):
        sink = Sink()
        ph = "11" * 32
        orphan_invoice, orphan_preimage = "22" * 32, "33" * 32
        # full Invoice-shaped record: the @stored_in('invoices')
        # conversion constructs Invoice objects from section values
        orphan_invoice_rec = {
            "message": "leftover", "amount_msat": 1000, "time": 1,
            "exp": 3600, "outputs": [], "bip70": None, "height": 0,
            "lightning_invoice": None,  # on-chain shape: bolt11 is optional
        }
        payload = _db_payload(
            {ph: _swap_rec(ph)},
            invoices={orphan_invoice: orphan_invoice_rec},
            lightning_preimages={orphan_preimage: "44" * 32},
        )
        sm = _make_sm(payload, sink)

        # orphans kept in place, only warned about
        assert orphan_invoice in sm._test_db.get_dict("invoices")
        assert orphan_preimage in sm._test_db.get_dict("lightning_preimages")
        warns = [m for m in sink.messages if m.startswith("WARNING")]
        assert sum("orphan payment entry" in m for m in warns) == 2
        assert any(orphan_invoice[:12] in m and "_invoices" in m for m in warns)
        assert any(orphan_preimage[:12] in m and "_preimages" in m for m in warns)
        infos = [m for m in sink.messages if "datastore loaded" in m]
        assert any("datastore loaded: 1 swaps, 0 quarantined, "
                   "2 orphan payments" in m for m in infos), sink.joined()
        assert sm.load_integrity == {"swaps": 1, "quarantined": 0,
                                     "orphans": 2,
                                     "missing_lockup_or_locktime": 0}

    def test_missing_lockup_address_locktime_warns(self):
        sink = Sink()
        ph = "55" * 32
        rec = _swap_rec(ph, lockup_address=None, locktime=None)
        sm = _make_sm(_db_payload({ph: rec}), sink)

        warns = [m for m in sink.messages if m.startswith("WARNING")]
        assert any("load-integrity" in m and ph[:12] in m
                   and "lockup_address" in m and "locktime" in m
                   for m in warns), sink.joined()
        assert sm.load_integrity["missing_lockup_or_locktime"] == 1
        assert ph in sm.swaps  # WARN, not quarantine/delete

    def test_quarantined_count_in_summary(self):
        sink = Sink()
        good, bad = "66" * 32, "77" * 32
        payload = _db_payload({
            good: _swap_rec(good),
            bad: _swap_rec(bad, privkey=""),
        })
        sm = _make_sm(payload, sink)
        infos = [m for m in sink.messages if "datastore loaded" in m]
        assert any("datastore loaded: 1 swaps, 1 quarantined, "
                   "0 orphan payments" in m for m in infos)
        assert sm.load_integrity["quarantined"] == 1


class TestHealthSurface:
    def _provider(self, sm=None):
        return SimpleNamespace(swap_manager=sm)

    def test_fields_present(self):
        sm = SimpleNamespace(
            quarantined_swaps={"aa": {}, "bb": {}},
            load_integrity={"swaps": 3, "quarantined": 2, "orphans": 1,
                            "missing_lockup_or_locktime": 0},
            swaps={}, invoices_to_pay={}, invoices_awaiting_funding=set(),
            _grace_hold_logged=set(), _grace_release_logged=set())
        report = build_report(self._provider(sm))
        assert report["quarantined_swaps"] == 2
        assert report["last_load_integrity"]["quarantined"] == 2
        assert report["last_load_integrity"]["swaps"] == 3
        json.dumps(report)  # RPC-serializable

    def test_fields_honest_when_missing(self):
        report = build_report(self._provider(SimpleNamespace()))
        assert report["quarantined_swaps"] == 0  # getattr(None or {})
        assert report["last_load_integrity"] is None

    def test_none_swap_manager_reports_none(self):
        report = build_report(self._provider(None))
        assert report["quarantined_swaps"] is None
        assert report["last_load_integrity"] is None
