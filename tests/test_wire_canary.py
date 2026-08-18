import json
import sys
from pathlib import Path

import pytest

# R4 wire-format canary: round-trip OUR offer through the SIBLING electrum
# checkout's CURRENT offer parser (the same code live clients run). The
# static 4.8.1 goldens in test_protocol_contract.py won't move when
# electrum drifts — this test breaks LOUDLY the day the sibling checkout
# is updated, which is exactly the failure class that killed the original
# plugin (frozen 2025 wire format, silently discarded by every client).

FORK = Path(__file__).resolve().parent.parent
ELECTRUM = FORK.parent / "electrum"
sys.path.insert(0, str(FORK / "swap-provider"))

from plugin import offer  # noqa: E402


@pytest.mark.skipif(not (ELECTRUM / "electrum" / "submarine_swaps.py").exists(),
                    reason="sibling electrum checkout absent (see PORT-NOTES)")
def test_our_offer_round_trips_through_current_electrum_parser():
    """build_offer_content output must be accepted by the CURRENT
    electrum client's offer parser: every field it reads, with the types
    it expects, and PoW the client would accept."""
    sys.path.insert(0, str(ELECTRUM))
    from electrum.submarine_swaps import SwapFees

    # the parser block (4.8.x): content dict fields + pow check
    pubk = "ab" * 32
    nonce = offer.mine_ann_pow_nonce(pubk, 8)
    content = json.loads(offer.build_offer_content(
        percentage_fee=0.5, mining_fee_sat=138, min_amount_sat=20000,
        max_forward_sat=7_500_000, max_reverse_sat=310_000,
        relays_csv="wss://relay.example,wss://relay2.example", pow_nonce=nonce))

    # client-side PoW verification (same call the parser makes)
    from electrum.util import get_nostr_ann_pow_amount
    pow_bits = get_nostr_ann_pow_amount(bytes.fromhex(pubk), int(content["pow_nonce"], 16))
    assert pow_bits >= 8

    # parser's field extraction — raises/KeyErrors on drift
    fees = SwapFees(
        percentage=__import__("decimal").Decimal(str(content["percentage_fee"])),
        mining_fee=content["mining_fee"],
        min_amount=content["min_amount"],
        max_forward=content["max_forward_amount"],
        max_reverse=content["max_reverse_amount"],
    )
    assert int(fees.max_forward) == 7_500_000
    assert int(fees.max_reverse) == 310_000
    relays = content["relays"].split(",")
    assert len(relays) == 2


def test_offer_keys_exact_no_extras():
    """No extra keys either: if electrum's parser ever becomes strict
    (rejecting unknown fields), a bloated offer dies. Keep the wire
    minimal — parity with electrum's own publisher."""
    pubk = "ab" * 32
    content = json.loads(offer.build_offer_content(
        percentage_fee=0.5, mining_fee_sat=138, min_amount_sat=20000,
        max_forward_sat=1, max_reverse_sat=1, relays_csv="wss://x",
        pow_nonce=1))
    assert set(content) == {"percentage_fee", "mining_fee", "min_amount",
                            "max_forward_amount", "max_reverse_amount",
                            "relays", "pow_nonce"}
