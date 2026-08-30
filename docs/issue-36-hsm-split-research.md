# #36 Research: HSM-Split of Claim Secrets — Complete Design Study
# (research + unit tests only, no implementation per owner directive 2026-08-30)

## Part 1: CLN's HSM internals (from source study + docs)

### The derivation chain

```
hsm_secret (root, 32 bytes legacy / 64 bytes BIP39 v25.12+)
  │
  ├─ HKDF-SHA256("bip32 seed") → bip32_seed (64 bytes)
  │   └─ BIP32 master key → wallet addresses (P2WPKH, P2TR)
  │
  ├─ HKDF-SHA256(...) → derived_secret (32 bytes, the makesecret IKM)
  │   │
  │   ├─ HKDF-SHA256("nodeid") → node private key (identity)
  │   ├─ HKDF-SHA256("bolt12-invoice-base") → BOLT12 invoice secret
  │   ├─ HKDF-SHA256("node-alias-base") → node alias key
  │   ├─ HKDF-SHA256("scb secret") → static channel backup
  │   └─ HKDF-SHA256(<our label>) → our per-swap claim key
  │
  └─ HKDF-SHA256("peer seed" + peer_id + channel_dbid) → channel seed
```

Source: `hsmd/libhsmd.c:312-325` (handle_derive_secret), `hsmd/hsmd.c` (populate_secretstuff)

### What makesecret actually does

```c
// hsmd/libhsmd.c:312-325
static u8 *handle_derive_secret(struct hsmd_client *c, const u8 *msg_in) {
    hkdf_sha256(&secret, sizeof(secret), NULL, 0,
                &secretstuff.derived_secret, sizeof(secretstuff.derived_secret),
                info, tal_bytelen(info));
    return towire_hsmd_derive_secret_reply(NULL, &secret);
}
```

**RFC 5869 HKDF-SHA256** with:
- Salt: NULL (none)
- Input Key Material: `secretstuff.derived_secret` (an intermediate key derived from bip32_seed)
- Info: the label string you provide
- Output: 32 bytes

### Security properties (from the HKDF spec + CLN's design)

| Property | What it means | Why it matters for us |
|---|---|---|
| **Deterministic** | Same hsm_secret + same label → same output | Claim key re-derivable on restart |
| **Hardened** | Leaking one derived key doesn't reveal others | One compromised swap doesn't compromise all |
| **One-way** | Can't recover hsm_secret from derived keys | Datastore leak doesn't expose the root |
| **Node-specific** | Different hsm_secret → different outputs | Cross-node: our keys don't work on other nodes |
| **No length extension** | HKDF is immune to SHA-256 extension attacks | Labels can't be manipulated |

### CLN's own uses (the precedent)

CLN uses `makesecret` / `derive_secret` for its own critical secrets:
- Node identity (private key)
- BIP32 wallet master key (all onchain funds)
- BOLT12 invoice secrets
- Channel seeds (all Lightning funds)
- Static channel backup

Our swap claim keys would be in the same security class.

### hsm_secret formats (v25.12+ change)

| Version | Format | Size | Notes |
|---|---|---|---|
| Pre-v25.12 | Raw binary | 32 bytes | Still supported (backward compat) |
| v25.12+ | BIP39 mnemonic | 12 words | Default for new nodes; optional passphrase |
| Either + encrypted | Encrypted | varies | `--hsm-passphrase` startup option |

**Important:** the hsm_secret format doesn't affect makesecret — the derivation chain handles both transparently (the BIP39 seed is converted to the same 32-byte root internally).

**Also important:** even with an encrypted hsm_secret, "lightningd always needs to access keys from the wallet which is thus not locked" — the RPC surface (including makesecret) is always available to anyone with RPC access. This is a documented CLN property, not a bug.

## Part 2: What we validated live (production signet, 2026-08-30)

### Determinism verified

```
$ lightning-cli makesecret string=test-derivation-label
  → 8d372130d0e6fa5723108a958175caf0aec5aebdc6b8e3ead95c7c03c166c79e

$ lightning-cli makesecret string=test-derivation-label
  → 8d372130d0e6fa5723108a958175caf0aec5aebdc6b8e3ead95c7c03c166c79e  (identical)
```

### secp256k1 validity verified

32 bytes, non-zero, < curve order, compressed pubkey derivable (03fedb86ae63e49e…).

### Datastore clean post-deploy

```
$ lightning-cli -k datastore key=swap-provider
  → entries: 0 (no active swaps, no secrets persisted)
```

### Our existing pattern (precedent in our own code)

```python
# plugin_config.py:51 — the nostr identity
nostr_secret = cln_plugin_handler.derive_secret("NOSTRSECRET")

# cln_lightning.py:76 — the payment secret key
self._payment_secret_key = plugin_instance.derive_secret("payment_secret")
```

Neither is stored in the datastore. Both are re-derived on every start.

## Part 3: Proposed design (Option B — both secrets HSM-derived)

### Claim key derivation

```python
# At swap creation (new code):
claim_privkey = derive_secret(f"swap-claim-{payment_hash.hex()}")
claim_pubkey = ECPrivkey(claim_privkey).get_public_key_bytes(compressed=True)
# Store: claim_pubkey (public), payment_hash (public)
# DON'T store: claim_privkey (re-derive at claim time)

# At claim time:
privkey = derive_secret(f"swap-claim-{swap.payment_hash.hex()}")
signature = sign(tx_hash, privkey)
```

### Preimage derivation (the chicken-and-egg resolution)

The payment_hash IS sha256(preimage) — we can't use the payment_hash as
a label to derive a preimage we haven't generated yet. Resolution: a
random SEED breaks the circularity.

```python
# At swap creation:
seed = os.urandom(16)  # random, safe to store
preimage = derive_secret(f"swap-preimage-{seed.hex()}")
payment_hash = sha256(preimage)
# Store: seed (safe), payment_hash (public)
# DON'T store: preimage (re-derive from seed + HSM)

# At claim time:
preimage = derive_secret(f"swap-preimage-{swap.preimage_seed.hex()}")
```

### What the datastore looks like (before vs after)

**Before (current):**
```json
{
  "privkey": "0123456789abcdef...",  // THE SECRET — readable by anyone with datastore access
  "preimage": "fedcba9876543210...",  // THE SECRET — enables claim construction
  "lockup_address": "bcrt1q...",
  "payment_hash": "abc123..."
}
```

**After (HSM-split):**
```json
{
  "claim_pubkey": "03fedb86ae...",    // public — safe
  "payment_hash": "abc123...",         // public — safe
  "preimage_seed": "0123456789abcdef", // safe: useless without HSM access
  "lockup_address": "bcrt1q..."       // public — safe
}
```

## Part 4: Threat model comparison

| Attacker | Before (current) | After (HSM-split) |
|---|---|---|
| Read datastore (`datastore` RPC or SQLite file) | ✅ Full sweep kit (privkey + preimage) | ❌ Gets public data + seed (useless without HSM) |
| Read CLN log (debug or error-replay) | ✅ If secrets logged (fixed: size-only logging) | ❌ Never logged |
| Filesystem access to `lightningd.sqlite` | ✅ Full sweep kit | ❌ Same as datastore read |
| CLN RPC access (any command) | ✅ Can call `datastore` to read secrets | ⚠️ Can call `makesecret` with our labels IF they know the format |
| Compromise `hsm_secret` file | ✅ Already game over (all funds) | ✅ Already game over (all funds) |
| Read backup of `lightningd.sqlite` | ✅ Full sweep kit | ❌ Seed only |

The **key change**: datastore/backup/log reads go from "complete sweep kit" to "useless without HSM." The remaining surface (RPC access) is within CLN's existing security boundary.

## Part 5: Migration path

### Strategy: per-swap, one-directional

```
At plugin startup:
  for each swap in self.swaps.values():
    if swap has 'privkey' field:
      # old-format swap (pre-HSM-split)
      # KEEP plaintext secrets (they can't be re-derived from HSM)
      # These swaps have bounded lifetimes (locktime + cleanup)
      log.warning(f"old-format swap {swap.payment_hash.hex()[:8]}: "
                  f"plaintext secrets retained until expiry")
    else:
      # new-format swap (post-HSM-split)
      # Secrets are HSM-derived; nothing to do
      pass
```

### Why old swaps can't be migrated

Old swaps' preimages were `os.urandom(32)` — randomly generated, not
HSM-derived. Even if we know the payment_hash, HSM derivation produces
a DIFFERENT preimage (not the one that was actually used). We verified
this in `TestMigrationEdgeCases::test_old_swap_preimage_cannot_be_hsm_rederived`.

### Cleanup

Old-format swaps expire via their locktime (70 blocks). The existing
`delete_finished_reverse_swap` / `_fail_swap` paths clean them up. Once
all old-format swaps are gone, the migration is complete.

## Part 6: Unit test coverage (22 tests, all passing)

| Test class | Tests | What they validate |
|---|---|---|
| `TestHkdfDerivation` | 5 | Determinism, label uniqueness, hardening, cross-node uniqueness, full-chain determinism |
| `TestSecp256k1Validity` | 5 | 32 bytes, non-zero, < curve order, pubkey derivable, live-verified output |
| `TestSeedBasedPreimageScheme` | 4 | Chicken-and-egg chain, no seed collisions, seed-alone insufficiency, claim key label |
| `TestDatastoreCleanliness` | 2 | Post-split record has no secrets, old-format record does |
| `TestMigrationEdgeCases` | 3 | New swaps use HSM, old preimages can't be re-derived, no label collisions |
| `TestSecurityProperties` | 3 | Datastore leak gives no secrets, RPC access can derive (documented), hardening across swaps |

The test file uses a local `hkdf_sha256` implementation (mirroring
CLN's ccan/crypto/hkdf_sha256) so all tests run without a CLN node.

## Part 7: Implementation checklist (for when the owner approves)

- [ ] Add `preimage_seed` field to `SwapData` (replaces `preimage` for new swaps)
- [ ] Add `claim_pubkey` field to `SwapData` (replaces `privkey` for new swaps)
- [ ] Modify `create_reverse_swap`: use `derive_secret` for both secrets
- [ ] Modify `_create_and_sign_claim_tx`: re-derive keys at sign time
- [ ] Modify `server_create_normal_swap`: return HSM-derived pubkey
- [ ] Add startup migration check: log old-format swaps with warning
- [ ] Verify datastore: `assert 'privkey' not in serialized_json` (add to test)
- [ ] Live test: swap end-to-end on regtest with HSM-derived keys
- [ ] Live test: restart plugin → same keys re-derived → claim succeeds
- [ ] Live test: read datastore → no secrets present
- [ ] Update README security section
- [ ] Deploy to signet/mutinynet

## References

- Issue #36 (this research's tracking issue)
- Issue #13 (the original secrets-exposure finding)
- CLN source: `hsmd/libhsmd.c:312-325` (handle_derive_secret)
- CLN source: `hsmd/hsmd.c` (populate_secretstuff, node_key)
- CLN docs: https://docs.corelightning.org/reference/makesecret
- CLN docs: https://docs.corelightning.org/docs/hsm-secret
- CLN docs: https://docs.corelightning.org/docs/securing-keys
- RFC 5869 (HKDF): https://tools.ietf.org/html/rfc5869
- Our existing pattern: `plugin_config.py:51` (nostr secret via derive_secret)
- Test file: `tests/test_hsm_split_design.py` (22 tests)
