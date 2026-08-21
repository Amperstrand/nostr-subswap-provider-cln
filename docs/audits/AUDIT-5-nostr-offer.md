# AUDIT-5: Nostr Offer Surface & PoW

## ROLE
You are a Nostr/Lightning protocol auditor. You audit THIS repo's nostr
offer announcement (the swap-server advertisement electrum clients
discover and TRUST) against the reference implementation.

## OBJECTIVE
The offer is the first thing every client validates — PoW, expiration,
network tag, fee fields. Any mismatch = clients silently ignore us (or
worse, accept a spoofable offer). Verdicts + divergence findings.

## INPUTS (read all)
- Impl: `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/offer.py`
  (all 82 lines: nostr_ann_pow_bits, mine_ann_pow_nonce,
  build_offer_content, build_offer_tags) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/submarine_swaps.py`
  (`NostrTransport` class ~line 990+: publish_offer, main_loop,
  check_direct_messages) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/cln_swap_provider.py`
- Reference: `/home/ubuntu/src/electrum/electrum/plugins/swapserver/swapserver.py`
  (electrum's current swapserver plugin — its offer construction, PoW
  mining, event kind/tags, relay handling, DM handling) and
  `/home/ubuntu/src/electrum/electrum/submarine_swaps.py` (client-side
  offer PARSING — what clients actually enforce: pow_nonce validation,
  expiration, fee field names, NOSTR_EVENT_VERSION, net tag matching)
- Tests pinning current behavior:
  `/home/ubuntu/src/nostr-subswap-provider-cln/tests/test_plugin_config_pow.py`
  and `/home/ubuntu/src/nostr-subswap-provider-cln/tests/test_protocol_contract.py`

## METHOD
1. PoW: electrum clients require NIP-13-style leading-zero bits of
   sha256("electrum-"+pubkey+nonce) ≥ target (default 30). Verify our
   mining + the exact string/data format matches electrum's VERIFIER
   (submarine_swaps.py client side), not just its miner. Off-by-one in
   the preimage string = wasted mining at best, rejected offers at worst.
2. Offer content fields: exact JSON keys + value semantics vs electrum's
   parser (fee_millionths vs percentage_fee naming, mining_fee units,
   max_forward/reverse amounts — sats or msat?).
3. Tags: kind 30315, 'd' tag electrum-swapserver-<ver> version match,
   expiration tag freshness window, 'r' net: tag correctness (recent
   commit 8c12e27 added ANN_NET_NAME — audit it), relay list.
4. DM round-trip: kind 25582 NIP-04 framing, reply-tag etiquette, error
   replies — compare to electrum client expectations.
5. Spoofing/DoS surface: what does our transport accept from arbitrary
   senders? Unauthenticated requests that mutate state? Replay of old
   DMs (id dedup)?
6. Rotation: offer expiration vs republication cadence — can the offer
   lapse while swaps are in flight?

## VERDICT FORMAT
Same as AUDIT-1 (N-<n> numbering).

## OUTPUT
Write to `/home/ubuntu/src/nostr-subswap-provider-cln/docs/audits/results/AUDIT-5-nostr-offer.md`
(header, N-table, DIVERGENCES, COVERAGE GAPS, FINDINGS SUMMARY, `VERDICT:` line).
