"""Traffic attribution (audit round 8, issue #24 operator directive:
strangers welcome on signet, attribution = monitoring NOT gating).

Covers: the TEST_NPUBS registry (normalize/parse/classify — explicit
registration only, no heuristics), per-request since-boot counters,
the DM-envelope recording primitive (requester_npub into the swap
record at creation, anti-spoof override of any client-supplied value,
first-writer-wins late fill at addswapinvoice), the swapprovider-swaps
RPC rows + swapprovider-health attribution block, the additive schema
(pre-r8 records load unchanged), and the NEVER-GATES contract on the
decision paths.

Run: python3 -m pytest tests/test_attribution.py -v
"""
import asyncio
import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
import sys
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

import plugin.submarine_swaps  # noqa: F401,E402  (registers SwapData)
from plugin import submarine_swaps as ss  # noqa: E402
from plugin import constants as constants_mod  # noqa: E402
from plugin.attribution import (  # noqa: E402
    attribution_tracker, attribution_health_section, classify_requester,
    describe_swap, list_recent_swaps, normalize_npub, parse_test_npubs,
    OURS, STRANGER, UNKNOWN)
from plugin.submarine_swaps import NostrTransport, SwapData, SwapManager  # noqa: E402

constants_mod.net = constants_mod.BitcoinRegtest()

HEX_A = "ab" * 32   # registered test client
HEX_B = "cd" * 32   # stranger
HEX_INVALID = "zz" * 32


@pytest.fixture(autouse=True)
def _fresh_attribution_tracker():
    attribution_tracker.reset()
    yield
    attribution_tracker.reset()


class TestRegistry:
    def test_hex_passthrough_normalized_lowercase(self):
        assert normalize_npub("AB" * 32) == HEX_A
        assert normalize_npub(HEX_A) == HEX_A

    def test_npub_decodes_to_hex(self):
        from electrum_aionostr.util import to_nip19
        npub = to_nip19("npub", HEX_A)
        assert npub.startswith("npub1")
        assert normalize_npub(npub) == HEX_A

    def test_junk_returns_none_never_raises(self):
        for junk in ("", "   ", None, 42, "npub1invalid!!", HEX_INVALID,
                     "ab" * 31, "ab" * 33, "hello"):
            assert normalize_npub(junk) is None

    def test_parse_csv_mixed_forms(self):
        from electrum_aionostr.util import to_nip19
        raw = f" {HEX_A} , {to_nip19('npub', HEX_B)}, junk , ,, {HEX_INVALID} , {HEX_A} "
        assert parse_test_npubs(raw) == (HEX_A, HEX_B)

    def test_parse_empty_absent(self):
        assert parse_test_npubs("") == ()
        assert parse_test_npubs("   ") == ()
        assert parse_test_npubs(None) == ()

    def test_classify_explicit_registration_only(self):
        reg = (HEX_A,)
        assert classify_requester(HEX_A, reg) == OURS
        assert classify_requester(HEX_A.upper(), reg) == OURS
        assert classify_requester(HEX_B, reg) == STRANGER
        assert classify_requester(None, reg) == UNKNOWN
        assert classify_requester("", reg) == UNKNOWN
        assert classify_requester(HEX_INVALID, reg) == UNKNOWN
        # empty registry: every known requester honestly reads stranger
        assert classify_requester(HEX_A, ()) == STRANGER


class TestRequestCounters:
    def test_counts_accumulate_per_label(self):
        attribution_tracker.note_request(OURS)
        attribution_tracker.note_request(OURS)
        attribution_tracker.note_request(STRANGER)
        assert attribution_tracker.snapshot() == {OURS: 2, STRANGER: 1, UNKNOWN: 0}

    def test_snapshot_is_a_copy(self):
        attribution_tracker.note_request(STRANGER)
        snap = attribution_tracker.snapshot()
        snap[STRANGER] = 99
        assert attribution_tracker.snapshot()[STRANGER] == 1


def _transport(test_npubs=(HEX_A,), handler_response=None):
    """NostrTransport without relays: only handle_request's collaborators."""
    t = NostrTransport.__new__(NostrTransport)
    t.logger = MagicMock()
    t.config = SimpleNamespace(test_npubs=test_npubs)
    t.sm = MagicMock()
    t.sm.is_initialized = asyncio.Event()
    t.sm.is_initialized.set()
    handler = AsyncMock(return_value=handler_response or {})
    t.sm.server_add_swap_invoice = handler
    t.sm.server_create_swap = handler
    t.sm.server_create_normal_swap = handler
    t.send_direct_message = AsyncMock(return_value="reply-event-id")
    return t


class TestHandleRequestAttribution:
    async def test_envelope_pubkey_recorded_spoof_overridden(self):
        t = _transport()
        request = {'method': 'createnormalswap', 'event_id': 'ev1',
                   'event_pubkey': HEX_B, 'invoiceAmount': 20000,
                   'refundPublicKey': '02' + '11' * 32,
                   # spoof attempt: client claims to be our test client
                   '_requester_npub': HEX_A}
        await t.handle_request(request)
        sent = t.sm.server_create_normal_swap.call_args[0][0]
        assert sent['_requester_npub'] == HEX_B  # envelope wins, always

    async def test_info_log_line_and_counter(self):
        t = _transport()
        await t.handle_request({'method': 'createswap', 'event_id': 'ev2',
                                'event_pubkey': HEX_B, 'type': 'reversesubmarine',
                                'pairId': 'BTC/BTC', 'invoiceAmount': 1000,
                                'preimageHash': '22' * 32,
                                'claimPublicKey': '02' + '33' * 32})
        logged = "\n".join(str(c) for c in t.logger.info.call_args_list)
        assert re.search(
            rf"swap request from npub={HEX_B} attributed={STRANGER}", logged)
        assert attribution_tracker.snapshot()[STRANGER] == 1

    async def test_registered_npub_attributed_ours(self):
        t = _transport()
        await t.handle_request({'method': 'addswapinvoice', 'event_id': 'ev3',
                                'event_pubkey': HEX_A, 'invoice': 'lntb1x'})
        logged = "\n".join(str(c) for c in t.logger.info.call_args_list)
        assert f"attributed={OURS}" in logged
        assert attribution_tracker.snapshot()[OURS] == 1

    async def test_unknown_method_not_counted_not_logged(self):
        t = _transport()
        await t.handle_request({'method': 'notaswapmethod', 'event_id': 'ev4',
                                'event_pubkey': HEX_B})
        logged = "\n".join(str(c) for c in t.logger.info.call_args_list)
        assert 'attributed=' not in logged
        assert attribution_tracker.snapshot() == {OURS: 0, STRANGER: 0, UNKNOWN: 0}

    async def test_reply_still_sent_attributed_stranger(self):
        # strangers are welcome traffic: attribution never blocks the reply
        t = _transport(handler_response={'id': 'deadbeef'})
        await t.handle_request({'method': 'createnormalswap', 'event_id': 'ev5',
                                'event_pubkey': HEX_B, 'invoiceAmount': 20000,
                                'refundPublicKey': '02' + '44' * 32})
        t.send_direct_message.assert_awaited_once()
        args = t.send_direct_message.await_args[0]
        assert args[0] == HEX_B
        assert json.loads(args[1])['id'] == 'deadbeef'


def _sm(**attrs) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm._grace_hold_logged = set()
    sm._grace_release_logged = set()
    sm._swaps_by_funding_outpoint = {}
    sm._swaps_by_lockup_address = {}
    sm.config = SimpleNamespace(network=constants_mod.BitcoinRegtest())
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1000)
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.register_address = AsyncMock()
    sm.lnworker = MagicMock()
    sm.lnworker.get_preimage = MagicMock(return_value=None)
    for k, v in attrs.items():
        setattr(sm, k, v)
    return sm


class TestRecordAtCreation:
    async def test_add_reverse_swap_records_requester_and_created_at(self):
        sm = _sm()
        swap = await sm.add_reverse_swap(
            redeem_script=b"\x51" * 10, locktime=5000, privkey=b"\x01" * 32,
            lightning_amount_sat=20000, onchain_amount_sat=21181,
            preimage=b"\xa1" * 32, payment_hash=b"\xbb" * 32,
            requester_npub=HEX_B)
        assert swap.requester_npub == HEX_B
        assert swap.created_at is not None and swap.created_at <= time.time()
        assert sm.swaps[(b"\xbb" * 32).hex()].requester_npub == HEX_B

    async def test_add_reverse_swap_without_npub_stays_none(self):
        sm = _sm()
        swap = await sm.add_reverse_swap(
            redeem_script=b"\x51" * 10, locktime=5000, privkey=b"\x01" * 32,
            lightning_amount_sat=20000, onchain_amount_sat=21181,
            preimage=b"\xa1" * 32, payment_hash=b"\xbb" * 32)
        assert swap.requester_npub is None

    async def test_add_normal_swap_records_requester(self):
        # prepay=True is the only live path (R4); prepay=False has a
        # pre-existing prepay_hash.hex() crash outside this round's scope
        sm = _sm()
        sm.prepayments = {}
        sm.lnworker.b11invoice_from_hash = MagicMock(
            return_value=SimpleNamespace(bolt11='lntb1fake'))
        sm.lnworker.create_payment_info = MagicMock(return_value=b'\xdd' * 32)
        sm.lnworker.bundle_payments = MagicMock()
        swap, b11, prepay = await sm.add_normal_swap(
            redeem_script=b"\x51" * 10, locktime=5000,
            onchain_amount_sat=21181, lightning_amount_sat=20000,
            payment_hash=b"\xcc" * 32, our_privkey=b"\x02" * 32,
            prepay=True, requester_npub=HEX_A)
        assert swap.requester_npub == HEX_A and swap.created_at is not None

    async def test_server_create_normal_swap_passes_envelope_npub(self):
        sm = _sm()
        fake_swap = SimpleNamespace(
            payment_hash=SimpleNamespace(hex=lambda: 'ee' * 32),
            onchain_amount=21181, locktime=5000,
            lockup_address='tb1qfake', redeem_script='51' * 10)
        sm.create_reverse_swap = AsyncMock(return_value=fake_swap)
        sm.lnworker.num_sats_can_send = MagicMock(return_value=10**9)
        await sm.server_create_normal_swap({
            'invoiceAmount': 20000, 'refundPublicKey': '02' + '55' * 32,
            '_requester_npub': HEX_B})
        sm.create_reverse_swap.assert_awaited_once_with(
            lightning_amount_sat=20000,
            their_pubkey=bytes.fromhex('02' + '55' * 32),
            requester_npub=HEX_B)

    async def test_server_create_swap_passes_envelope_npub(self):
        sm = _sm()
        fake = (SimpleNamespace(lockup_address='a', redeem_script='51' * 10,
                                onchain_amount=1, locktime=1), 'b11', None)
        sm.create_normal_swap = AsyncMock(return_value=fake)
        sm.lnworker.num_sats_can_receive = MagicMock(return_value=10**9)
        sm.wallet.balance_sat = MagicMock(return_value=10**9)
        await sm.server_create_swap({
            'type': 'reversesubmarine', 'pairId': 'BTC/BTC',
            'invoiceAmount': 1000, 'preimageHash': '22' * 32,
            'claimPublicKey': '02' + '66' * 32, '_requester_npub': HEX_A})
        sm.create_normal_swap.assert_awaited_once_with(
            lightning_amount_sat=1000, payment_hash=bytes.fromhex('22' * 32),
            their_pubkey=bytes.fromhex('02' + '66' * 32),
            requester_npub=HEX_A)


def _d2_record(sm, *, requester_npub=None, their_pubkey=None):
    """A REAL bindable d2 record: privkey/preimage/locktime/redeem_script
    mutually consistent so server_add_swap_invoice's re-derivation passes."""
    from electrum_ecc import ECPrivkey
    from plugin.bitcoin import construct_script
    from plugin.submarine_swaps import WITNESS_TEMPLATE_REVERSE_SWAP
    privkey = b"\x07" * 32
    preimage = b"\xa1" * 32
    payment_hash = ss.sha256(preimage)
    their_pubkey = their_pubkey or ECPrivkey(b"\x08" * 32).get_public_key_bytes(compressed=True)
    our_pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    locktime = 5000
    redeem_script = construct_script(
        WITNESS_TEMPLATE_REVERSE_SWAP,
        {1: 32, 5: ss.ripemd(payment_hash), 7: our_pubkey,
         10: locktime, 13: their_pubkey})
    swap = SwapData(
        is_reverse=True, locktime=locktime, onchain_amount=21181,
        lightning_amount=20000, redeem_script=redeem_script,
        preimage=preimage, prepay_hash=None, privkey=privkey,
        lockup_address='tb1qfake', receive_address='', funding_txid=None,
        spending_txid=None, is_redeemed=False, registered=False,
        requester_npub=requester_npub)
    swap._payment_hash = payment_hash.hex()
    sm.swaps[swap._payment_hash] = swap
    return swap, their_pubkey


def _fake_invoice(rhash, amount_sat):
    return SimpleNamespace(rhash=rhash, lightning_invoice='lntb1x',
                           get_amount_sat=lambda: amount_sat,
                           has_expired=lambda: False)


class TestLateFillAtAddswapinvoice:
    def _bindable_sm(self):
        sm = _sm()
        sm.lnworker.get_invoice = MagicMock(return_value=None)
        sm.lnworker.save_invoice = MagicMock()
        return sm

    def _bind(self, sm, swap, their_pubkey, requester):
        invoice = _fake_invoice(swap._payment_hash, swap.lightning_amount)
        orig = ss.Invoice.from_bech32
        ss.Invoice.from_bech32 = staticmethod(lambda b11: invoice)
        orig_check = ss.check_invoice_before_payment
        ss.check_invoice_before_payment = lambda b11: None
        try:
            sm.server_add_swap_invoice({
                'invoice': 'lntb1real', 'refundPublicKey': their_pubkey.hex(),
                '_requester_npub': requester})
        finally:
            ss.Invoice.from_bech32 = orig
            ss.check_invoice_before_payment = orig_check

    def test_none_npub_filled_from_registrant(self):
        sm = self._bindable_sm()
        swap, their_pk = _d2_record(sm, requester_npub=None)
        self._bind(sm, swap, their_pk, HEX_B)
        assert swap.registered is True
        assert swap.requester_npub == HEX_B
        assert swap._payment_hash in sm.invoices_awaiting_funding

    def test_existing_npub_never_overwritten(self):
        sm = self._bindable_sm()
        swap, their_pk = _d2_record(sm, requester_npub=HEX_A)  # phase-1 owner
        self._bind(sm, swap, their_pk, HEX_B)                  # someone else binds
        assert swap.requester_npub == HEX_A


class TestSwapRowsAndStates:
    def _row_swap(self, **kw):
        s = SwapData(
            is_reverse=kw.get('is_reverse', True), locktime=5000,
            onchain_amount=21181, lightning_amount=20000,
            redeem_script='51' * 10, preimage='a1' * 32, prepay_hash=None,
            privkey='01' * 32, lockup_address='tb1qfake', receive_address='',
            funding_txid=kw.get('funding_txid'), spending_txid=kw.get('spending_txid'),
            is_redeemed=kw.get('is_redeemed', False),
            requester_npub=kw.get('requester_npub'),
            created_at=kw.get('created_at'))
        s._payment_hash = kw.get('payment_hash', 'bb' * 32)
        return s

    def test_state_ladder(self):
        sm = SimpleNamespace(invoices_awaiting_funding=set(), invoices_to_pay={})
        key = 'bb' * 32
        cases = [
            ({}, 'created'),
            ({'funding_txid': 'f' * 64}, 'funded'),
            ({'funding_txid': 'f' * 64, 'spending_txid': 's' * 64}, 'claimed'),
            ({'is_redeemed': True, 'funding_txid': 'f' * 64,
              'spending_txid': 's' * 64}, 'redeemed'),
        ]
        for kwargs, expected in cases:
            assert describe_swap(self._row_swap(**kwargs), sm, ())['state'] == expected
        s = self._row_swap()
        sm.invoices_awaiting_funding.add(key)
        assert describe_swap(s, sm, ())['state'] == 'awaiting_lockup'
        sm.invoices_awaiting_funding.clear()
        sm.invoices_to_pay[key] = 0
        assert describe_swap(s, sm, ())['state'] == 'paying'

    def test_direction_house_names(self):
        sm = SimpleNamespace(invoices_awaiting_funding=set(), invoices_to_pay={})
        assert describe_swap(self._row_swap(is_reverse=True), sm, ())['direction'] == 'onchain_to_ln'
        assert describe_swap(self._row_swap(is_reverse=False), sm, ())['direction'] == 'ln_to_onchain'

    def test_attributed_labels_and_age(self):
        sm = SimpleNamespace(invoices_awaiting_funding=set(), invoices_to_pay={})
        row = describe_swap(self._row_swap(requester_npub=HEX_A, created_at=time.time() - 90),
                            sm, (HEX_A,))
        assert row['attributed'] == OURS and 89 <= row['age_sec'] <= 95
        assert describe_swap(self._row_swap(requester_npub=HEX_B), sm, ())['attributed'] == STRANGER
        pre_r8 = describe_swap(self._row_swap(), sm, ())
        assert pre_r8['attributed'] == UNKNOWN and pre_r8['age_sec'] is None


class TestListRecentSwaps:
    def _provider(self, swaps):
        sm = SimpleNamespace(swaps=swaps)
        return SimpleNamespace(swap_manager=sm, config=SimpleNamespace(test_npubs=(HEX_A,)))

    def _swap(self, key, npub, created_at):
        s = TestSwapRowsAndStates()._row_swap(requester_npub=npub, created_at=created_at,
                                              payment_hash=key)
        return s

    def test_newest_first_labels_counts_limit(self):
        swaps = {s._payment_hash: s for s in [
            self._swap('11' * 32, HEX_A, 300.0),
            self._swap('22' * 32, HEX_B, 200.0),
            self._swap('33' * 32, None, 100.0)]}
        report = list_recent_swaps(self._provider(swaps))
        assert [r['payment_hash'][:2] for r in report['swaps']] == ['11', '22', '33']
        assert [r['attributed'] for r in report['swaps']] == [OURS, STRANGER, UNKNOWN]
        assert report['attributed_live'] == {OURS: 1, STRANGER: 1, UNKNOWN: 1}
        assert report['total_live'] == 3 and report['test_npubs_registered'] == 1
        limited = list_recent_swaps(self._provider(swaps), limit=2)
        assert limited['count'] == 2 and limited['total_live'] == 3

    def test_limit_bounds_and_junk(self):
        swaps = {f'{i:02x}' * 32: self._swap(f'{i:02x}' * 32, None, float(i))
                 for i in range(3)}
        p = self._provider(swaps)
        assert list_recent_swaps(p, limit=999)['count'] == 3      # capped at 100, len 3
        assert list_recent_swaps(p, limit='junk')['count'] == 3   # falls back to default
        assert list_recent_swaps(p, limit=0)['count'] == 0

    def test_no_swap_manager_answers_honestly(self):
        report = list_recent_swaps(SimpleNamespace(swap_manager=None))
        assert report['swaps'] == [] and 'not initialized' in report['note']

    def test_json_serializable(self):
        swaps = {'44' * 32: self._swap('44' * 32, HEX_A, 1.0)}
        json.dumps(list_recent_swaps(self._provider(swaps)))


class TestHealthAttributionBlock:
    def test_health_report_carries_attribution_counters(self):
        from plugin.health import build_report, tracker as health_tracker
        health_tracker.reset()
        attribution_tracker.note_request(OURS)
        attribution_tracker.note_request(STRANGER)
        sm = SimpleNamespace(swaps={'55' * 32: TestSwapRowsAndStates()._row_swap(requester_npub=HEX_A)})
        provider = SimpleNamespace(config=SimpleNamespace(test_npubs=(HEX_A,),
                                                          sweep_grace_blocks=2),
                                   swap_manager=sm)
        report = build_report(provider)
        attr = report['attribution']
        assert attr['test_npubs_registered'] == 1
        assert attr['requests_since_boot'] == {OURS: 1, STRANGER: 1, UNKNOWN: 0}
        assert attr['live_swaps'] == {OURS: 1, STRANGER: 0, UNKNOWN: 0}
        json.dumps(report)

    def test_attribution_section_before_init(self):
        section = attribution_health_section(SimpleNamespace(spec=[]))
        assert section['test_npubs_registered'] is None
        assert section['live_swaps'] is None
        assert section['requests_since_boot'] == {OURS: 0, STRANGER: 0, UNKNOWN: 0}


class TestSchemaAdditive:
    """The r8 fields are additive: pre-r8 records (the 35-record
    production shape) load unchanged; r8 records round-trip."""

    def _db_with(self, records):
        from plugin.json_db import JsonDB

        class MemStorage:
            def __init__(self, payload):
                self._payload = payload
            def read(self):
                return self._payload
            def write(self, data):
                pass
            def append(self, data):
                pass
            def needs_consolidation(self):
                return False

        payload = json.dumps({"submarine_swaps": records}, indent=4, sort_keys=True)
        storage = MemStorage(payload)
        return JsonDB(s=storage.read(), storage=storage, logger=MagicMock())

    def _base_record(self):
        return {"is_reverse": True, "locktime": 5000, "onchain_amount": 21181,
                "lightning_amount": 20000, "redeem_script": "51" * 10,
                "preimage": "a1" * 32, "prepay_hash": None,
                "privkey": "01" * 32, "lockup_address": "tb1qfake",
                "receive_address": "", "funding_txid": None,
                "spending_txid": None, "is_redeemed": False,
                "registered": True}

    def test_pre_r8_records_load_with_none_fields(self):
        db = self._db_with({'aa' * 32: self._base_record()})
        swaps = db.get_dict('submarine_swaps')
        swap = swaps['aa' * 32]
        assert isinstance(swap, SwapData)
        assert swap.requester_npub is None and swap.created_at is None

    def test_r8_records_round_trip(self):
        rec = self._base_record()
        rec['requester_npub'] = HEX_B
        rec['created_at'] = 1750000000.5
        db = self._db_with({'bb' * 32: rec})
        swap = db.get_dict('submarine_swaps')['bb' * 32]
        assert swap.requester_npub == HEX_B and swap.created_at == 1750000000.5


class TestNeverGatesContract:
    """Code-inspection (the repo's contract-test style): attribution is
    monitoring only. The swap DECISION paths must not consult the
    registry or the label; only the transport (logging/recording) and
    the observability surfaces may."""

    def _code(self, name):
        return (_plugin / name).read_text()

    def test_decision_paths_blind_to_attribution(self):
        for fname in ('submarine_swaps.py',):
            code = self._code(fname)
            # strip comments so only executable references count
            code = re.sub(r'#.*', '', code)
            for fn_name in ('server_add_swap_invoice', 'server_create_swap',
                            'server_create_normal_swap', '_evaluate_funding_gate',
                            '_claim_swap', 'hold_invoice_callback'):
                body = re.search(rf'def {fn_name}\(.*?(?=\n    (?:async )?def |\nclass |\Z)',
                                 code, re.S)
                assert body is not None, f'{fn_name} not found in {fname}'
                assert 'classify_requester' not in body.group(0), \
                    f'{fn_name} must not classify (gating risk)'
                assert 'test_npubs' not in body.group(0), \
                    f'{fn_name} must not read the registry (gating risk)'

    def test_transport_records_and_labels(self):
        code = re.sub(r'#.*', '', self._code('submarine_swaps.py'))
        assert "request['_requester_npub'] = event_pubkey" in code
        assert 'classify_requester' in code  # the ONLY decision-site user is the log line

    def test_config_reads_test_npubs_env(self):
        code = self._code('plugin_config.py')
        assert "os.getenv(\"TEST_NPUBS\"" in code

    def test_rpc_registered(self):
        code = self._code('cln_swap_provider.py')
        assert '"swapprovider-swaps"' in code and '"swapprovider-health"' in code
