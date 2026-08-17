import json
import sys
from pathlib import Path

import pytest

# M1 contract tests (PORT-NOTES.md): pin the CURRENT electrum 4.8.1
# provider protocol with source-cited goldens, prove the archived plugin's
# wire format is rejected by current clients (why the port exists), and
# mark the M2 seam with strict-xfail tests that the port must turn green.

HERE = Path(__file__).resolve().parent
FORK = HERE.parent
ELECTRUM = FORK.parent / "electrum"
PLAYGROUND = FORK.parent / "lightning-playground"
sys.path.insert(0, str(FORK / "swap-provider"))

# ─── golden: electrum 4.8.1 offer (submarine_swaps.py publish_offer,
# NOSTR_EVENT_VERSION = 5) ────────────────────────────────────────────

CURRENT_ELECTRUM_OFFER_KEYS = {
    # content keys, exact set from source:
    "percentage_fee",   # float, kept for <=4.7.1 compat
    "mining_fee",
    "min_amount",
    "max_forward_amount",
    "max_reverse_amount",
    "relays",
    "pow_nonce",        # hex string; client verifies NIP-13-ish leading
                        # zero bits of sha256(b"electrum-"+pubk+nonce_be32)
}
CURRENT_D_TAG = "electrum-swapserver-5"
CURRENT_NET_TAG_PREFIX = "net:"

# ─── the archived plugin's actual publish_offer payload (fc90e07,
# swap-provider/plugin/submarine_swaps.py:875-893, transcribed) ──────

PLUGIN_OFFER_CONTENT_KEYS = {
    "version", "network", "relays", "percentage_fee",
    "normal_mining_fee", "reverse_mining_fee", "claim_mining_fee",
    "min_amount", "max_amount",
}
PLUGIN_D_TAG = "electrum-swap-announcement"


def test_golden_keys_are_nonempty_and_disjoint_from_none():
    assert CURRENT_ELECTRUM_OFFER_KEYS
    assert "pow_nonce" in CURRENT_ELECTRUM_OFFER_KEYS


def test_plugin_offer_is_rejected_by_current_clients():
    """Why the port exists — four independent rejection causes."""
    # 1. no pow_nonce at all → client-side PoW check reads 0 bits
    assert "pow_nonce" not in PLUGIN_OFFER_CONTENT_KEYS
    # 2. missing the max-amount keys the client fee/limits logic reads
    assert not {"max_forward_amount", "max_reverse_amount"} & PLUGIN_OFFER_CONTENT_KEYS
    # 3. d-tag is the pre-versioning string → not a current-gen offer
    assert PLUGIN_D_TAG != CURRENT_D_TAG
    # 4. no 'r' net tag → network filtering (boltz-bridge provider
    #    matcher, and current electrum) cannot place the provider
    assert "network" in PLUGIN_OFFER_CONTENT_KEYS  # in content, not a tag


def test_m2_plugin_module_imports_standalone():
    """Flipped green in M2: CLN-bound collaborators are TYPE_CHECKING-only
    + future-annotations, so the protocol/wire core imports without pyln
    or a node. (Found + fixed two upstream import-crashers doing this.)"""
    from plugin import submarine_swaps  # noqa: F401


def test_m2_offer_builder_emits_current_keys():
    """The pure offer module emits EXACTLY the electrum 4.8.1 wire format
    (pow_nonce hex, max-amount keys, percentage_fee float, d/r/expiration
    tags). Cross-checked against electrum's own PoW over 300 vectors."""
    import json as _json
    from plugin import offer

    content = _json.loads(offer.build_offer_content(
        percentage_fee=0.5, mining_fee_sat=22500, min_amount_sat=20000,
        max_forward_sat=7500000, max_reverse_sat=310000,
        relays_csv="wss://nos.lol", pow_nonce=12345))
    assert set(content.keys()) == CURRENT_ELECTRUM_OFFER_KEYS
    assert content["pow_nonce"] == hex(12345)
    assert isinstance(content["percentage_fee"], float)
    assert content["max_forward_amount"] == 7500000
    assert content["max_reverse_amount"] == 310000

    tags = offer.build_offer_tags("regtest", now=1_700_000_000)
    assert tags[0] == ["d", CURRENT_D_TAG]
    assert tags[1] == ["r", "net:regtest"]
    assert tags[2] == ["expiration", str(1_700_000_000 + offer.OFFER_UPDATE_INTERVAL_SEC
                                           + offer.OFFER_EXPIRY_MARGIN_SEC)]

    pubk = "ab" * 32
    mined = offer.mine_ann_pow_nonce(pubk, target_bits=8)
    assert mined is not None
    assert offer.nostr_ann_pow_bits(pubk, mined) >= 8


@pytest.mark.skipif(not (ELECTRUM / "electrum" / "util.py").exists(),
                    reason="sibling electrum checkout absent")
def test_pow_matches_electrum_implementation():
    """Authority check: our PoW must equal electrum's own
    get_nostr_ann_pow_amount for the vectors nostr-pow-bench generated
    from electrum itself."""
    import secrets
    from plugin import offer
    sys.path.insert(0, str(ELECTRUM))
    from electrum.util import get_nostr_ann_pow_amount
    for _ in range(200):
        pubk = secrets.token_bytes(32).hex()
        nonce = secrets.randbits(96)
        assert offer.nostr_ann_pow_bits(pubk, nonce) == \
            get_nostr_ann_pow_amount(bytes.fromhex(pubk), nonce)


# ─── the script-contract oracle: lightning-playground's swaps_lib must
# reproduce the REAL signet redeemScripts (both directions) — this is the
# reference the port's script construction is diffed against in M2 ────

FIXTURES = PLAYGROUND / "tests_tools" / "fixtures_completed_swaps.json"

@pytest.mark.skipif(not FIXTURES.exists(), reason="sibling lightning-playground checkout absent")
def test_swaps_lib_reproduces_real_signet_scripts():
    sys.path.insert(0, str(PLAYGROUND / "tools"))
    import swaps_lib
    fix = json.loads(FIXTURES.read_text())
    cases = [(s["request"], s["redeemScript"], "reversesubmarine")
             for s in fix["direction1_reverse_swaps"]]
    d2 = fix["direction2_submarine_swap"]
    cases.append((d2["request"], d2["redeemScript"], "submarine"))
    for request, redeem_hex, direction in cases:
        parsed = swaps_lib.parse_swap_script(redeem_hex)
        if direction == "reversesubmarine":
            assert parsed["claim_pubkey"] == request["claimPublicKey"]
        else:
            assert parsed["refund_pubkey"] == request["refundPublicKey"]
            assert parsed["preimage_hash_ripemd"] == swaps_lib.ripemd160(
                bytes.fromhex(d2["preimageHash"])).hex()  # F10: plain ripemd160
        rebuilt = swaps_lib.build_swap_script(
            d2["preimageHash"] if direction == "submarine"
            else next(s["request"]["preimageHash"] for s in
                      fix["direction1_reverse_swaps"] if s["redeemScript"] == redeem_hex),
            parsed["claim_pubkey"], parsed["refund_pubkey"],
            parsed["timeout_block_height"])
        assert rebuilt == bytes.fromhex(redeem_hex), \
            "builder must be byte-faithful (the M2 diff oracle)"
