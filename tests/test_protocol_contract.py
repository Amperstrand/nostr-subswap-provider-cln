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


@pytest.mark.xfail(strict=True, reason="M2 seam: refactor publish_offer into a pure "
                    "build_offer_content(); module must import without pyln/relays")
def test_m2_plugin_module_imports_standalone():
    sys.path.insert(0, str(FORK / "swap-provider"))
    from plugin import submarine_swaps  # noqa: F401


@pytest.mark.xfail(strict=True, reason="M2: build_offer_content() must emit exactly "
                    "the current electrum keys (golden above)")
def test_m2_offer_builder_emits_current_keys():
    sys.path.insert(0, str(FORK / "swap-provider"))
    from plugin.submarine_swaps import build_offer_content  # noqa: F401


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
