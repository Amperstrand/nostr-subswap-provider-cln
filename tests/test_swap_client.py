"""Client-mode unit tests, pinned to LIVE e2e values.

Every constant below is from the first fully-completed swap on
mutinynet (2026-08-25, NOSTR-SWAP.md 10.8): the claim witness
revealed the preimage; the DB row gave the payment hash and
timeout; the script came out of the witness stack.  These tests
are the Python twin of the C++ regressions (clboss
tests/nostr/test_createswap_validation.cpp) -- same values, both
implementations, drift anywhere fails loudly.
"""
import hashlib
import sys
import time

import pytest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))

from plugin.swap_client import (  # noqa: E402
    ClientOffer, SwapClientError, build_lockup_script, decode_script_num,
    encode_script_num, parse_redeem_script)

# --- the live swap (claim 82458da9..., lockup 13065c57...) ------------
PREIMAGE = bytes.fromhex(
    "a39a30a6977e5e4e01f6f95a9c55bcac"
    "912e02573f0936504afdd50fa80baac3")
PAYMENT_HASH = bytes.fromhex(
    "6bf31e1d336474143d084ff047819ea1"
    "d2d9d118a633bd35bc8d5b3dc8bdce14")
CLAIM_KEY = bytes.fromhex(
    "037be23dfe9461fa89cf458a2b56a543c9"
    "c6e24f7a489fa641c07da2b7b77b7207")
REFUND_KEY = bytes.fromhex(
    "0379b2dc6b46cbc2c316c2a22e44593df0"
    "1faf7f65c455acddf9cf7bb5ee183a02")
LOCKTIME = 3374111           # witness push bytes 1f 7c 33 (LE)
CREATION_HEIGHT = 3374022    # timeout - 89 blocks
ONCHAIN = 20000

LIVE_SCRIPT = build_lockup_script(
    PAYMENT_HASH, CLAIM_KEY, LOCKTIME, REFUND_KEY)


def ripemd(b):
    return hashlib.new('ripemd160', b).digest()


def test_preimage_binds_payment_hash():
    assert hashlib.sha256(PREIMAGE).digest() == PAYMENT_HASH


def test_builder_is_live_witness():
    """The generator must reproduce the witness script byte-for-byte
    (106 bytes, hash160 slot 68b97d40..., LE push 1f 7c 33)."""
    live = bytes.fromhex(
        "8201208763a91468b97d40b915d510cd9bcd852aed1af0dcb54389"
        "8821"
        "037be23dfe9461fa89cf458a2b56a543c9c6e24f7a489fa641c07da"
        "2b7b77b7207"
        "6775"
        "031f7c33"
        "b17521"
        "0379b2dc6b46cbc2c316c2a22e44593df01faf7f65c455acddf9cf"
        "7bb5ee183a02"
        "68ac")
    assert LIVE_SCRIPT == live


def test_parse_live_script():
    parsed = parse_redeem_script(LIVE_SCRIPT)
    assert parsed['locktime'] == LOCKTIME
    assert parsed['claim_pubkey'] == CLAIM_KEY
    assert parsed['refund_pubkey'] == REFUND_KEY
    assert parsed['hash160'] == ripemd(PAYMENT_HASH)


def test_decode_script_num_endianness():
    # the witness bytes: LE -> 3374111; BE would misread 0x1f7c33
    assert decode_script_num(bytes.fromhex('1f7c33')) == 3374111
    assert decode_script_num(b'') == 0
    assert decode_script_num(b'\x01') == 1
    # 30000 = 0x7530 -> LE 30 75 (top byte 0x75 clear of the sign bit)
    assert decode_script_num(b'\x30\x75') == 30000
    # 40000's LE encoding has the sign bit set (0x9c) and is
    # therefore NOT a valid positive CScriptNum at 2 bytes
    assert decode_script_num(b'\x40\x9c') == -1
    # sign bit set -> rejected as negative
    assert decode_script_num(b'\x01\x80') == -1


def test_encode_decode_roundtrip():
    for n in (17, 255, 256, 40000, 3374111, 16000000):
        enc = encode_script_num(n)
        assert decode_script_num(enc[1:]) == n


def test_forged_be_script_rejected():
    """SECURITY (advisory 14): BE-encoded declared timeout must fail
    the LE decode -- crafted bytes 01 00 00 read as 65536 BE but
    enforce CLTV 1 on-chain (refund-now while the client believes
    65536).  The old dual-decode acceptance shipped exactly this
    hole; the C++ attack regression pins the same pair."""
    forged = build_lockup_script(
        PAYMENT_HASH, CLAIM_KEY, 65536, REFUND_KEY)
    le = encode_script_num(65536)
    assert le == bytes([3, 0x00, 0x00, 0x01])  # 03 00 00 01
    be = bytes([3, 0x01, 0x00, 0x00])         # 03 01 00 00
    idx = forged.index(le)
    crafted = forged[:idx] + be + forged[idx + 4:]
    parsed = parse_redeem_script(crafted)
    # the chain enforces LE: 0x000001 = 1, not 65536
    assert parsed['locktime'] == 1


def test_direction_trap_detected():
    """Keys swapped into the wrong slots: our key on the refund branch
    (we could never spend the preimage path)."""
    swapped = build_lockup_script(
        PAYMENT_HASH, REFUND_KEY, LOCKTIME, CLAIM_KEY)
    parsed = parse_redeem_script(swapped)
    assert parsed['claim_pubkey'] != CLAIM_KEY


def test_wrong_hash_slot_detected():
    other = build_lockup_script(bytes(32), CLAIM_KEY, LOCKTIME, REFUND_KEY)
    parsed = parse_redeem_script(other)
    assert parsed['hash160'] != ripemd(PAYMENT_HASH)


def _offer_event(pct=0.2, mining=200, pow_nonce='0x1c', age=60):
    return SimpleNamespace(
        pubkey='aa' * 32,
        created_at=int(time.time()) - age,
        content='{"percentage_fee": %s, "mining_fee": %d, '
                '"min_amount": 20000, "max_forward_amount": 9000000, '
                '"max_reverse_amount": 900000, '
                '"relays": "wss://a,wss://b", "pow_nonce": "%s"}'
                % (pct, mining, pow_nonce))


def test_offer_gates():
    assert ClientOffer(_offer_event(pow_nonce='0x0'), pow_target=0)
    with pytest.raises(SwapClientError):
        ClientOffer(_offer_event(pow_nonce='0x0'), pow_target=30)
    with pytest.raises(SwapClientError):
        ClientOffer(_offer_event(age=7200), pow_target=0)


def test_offer_quote():
    o = ClientOffer(_offer_event(pct=0.2, mining=200), pow_target=0)
    # 100k sats at 0.2% (=200) + 200 mining -> 99600
    assert o.quote_onchain(100000) == 100000 - 200 - 200
    assert ClientOffer(
        _offer_event(pct=100, mining=999999999),
        pow_target=0).quote_onchain(1000) is None
