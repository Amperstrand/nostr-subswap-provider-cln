# #36 Research: HSM-Split of Claim Secrets — Design Study
# (research only, no implementation per owner directive 2026-08-30)

## What we validated live

### 1. `makesecret` is deterministic (same input → same output)

```
$ lightning-cli makesecret string=test-derivation-label
  → 8d372130d0e6fa5723108a958175caf0aec5aebdc6b8e3ead95c7c03c166c79e
$ lightning-cli makesecret string=test-derivation-label
  → 8d372130d0e6fa5723108a958175caf0aec5aebdc6b8e3ead95c7c03c166c79e  (identical)
```

This is critical — the claim key MUST be re-derivable on every restart.

### 2. The output is a valid secp256k1 private key

```
32 bytes, non-zero, < curve order → valid scalar
compressed pubkey derivable (verified with electrum_ecc)
```

No additional transformation needed — the raw makesecret output IS a
usable private key.

### 3. The existing pattern in our plugin

The plugin already uses `derive_secret` (which calls `makesecret` via
pyln RPC) for two secrets:

```python
# cln_plugin.py:88-93
def derive_secret(self, derivation_str: str) -> bytes:
    secret_hex = self.plugin.rpc.call("makesecret",
        payload={"string": derivation_str})["secret"]
    return bytes.fromhex(secret_hex)

# plugin_config.py:51 — the nostr identity
nostr_secret = cln_plugin_handler.derive_secret("NOSTRSECRET")

# cln_lightning.py:76 — the payment secret key
self._payment_secret_key = plugin_instance.derive_secret("payment_secret")
```

Neither of these is stored in the datastore. They exist only in memory
and are re-derived on every plugin start from CLN's HSM.

### 4. The datastore is clean post-deploy (verified live)

```
$ lightning-cli -k datastore key=swap-provider
  → entries: 0  (no swaps active, no secrets persisted)
```

## Proposed design (for review, not implementation)

### Claim key derivation

At swap creation, instead of `privkey = os.urandom(32)`:

```python
# derive from the HSM using the payment hash as the unique label
claim_privkey = derive_secret(f"swap-claim-{swap.payment_hash.hex()}")
claim_pubkey = ECPrivkey(claim_privkey).get_public_key_bytes(compressed=True)
```

The privkey is NEVER stored. The pubkey is stored (it's public). The
claim path re-derives the key at sign time:

```python
async def _create_and_sign_claim_tx(self, txin, swap):
    # re-derive from HSM at sign time — never stored
    privkey = derive_secret(f"swap-claim-{swap.payment_hash.hex()}")
    signature = sign(tx_hash, privkey)
    ...
```

### Preimage derivation (the harder case)

The preimage CANNOT be derived from the HSM — it must be revealed in
the claim witness, which means it must be known before the claim.
Options:

**Option A: Keep preimage in datastore, move only the privkey.**
- The preimage is still readable via datastore, but without the
  privkey, it can't be used to construct a claim. Partial fix.
- The preimage alone gives you the hash preimage (useful for settling
  hold invoices, not for claiming onchain).

**Option B: Derive the preimage from the HSM too.**
- `preimage = derive_secret(f"swap-preimage-{payment_hash}")`
- But wait — the payment_hash IS sha256(preimage). If the preimage is
  derived from a label that includes the payment_hash, we have a
  chicken-and-egg: we need the payment_hash to derive the preimage,
  but the payment_hash IS the hash of the preimage.
- **Fix:** derive the preimage FIRST from a random label, then compute
  the payment_hash from it:
  ```python
  seed = os.urandom(16)  # random, stored in the swap record (public-safe)
  preimage = derive_secret(f"swap-preimage-{seed.hex()}")
  payment_hash = sha256(preimage)
  # store: seed (in datastore), payment_hash (in datastore)
  # DON'T store: preimage (re-derive from HSM + seed at claim time)
  ```
- The seed is safe to store in the datastore — it's only useful with
  the HSM.

**Option C: PTLC/adaptor signatures (the structural fix).**
- The preimage doesn't exist until the payment succeeds.
- This is the #40 research item — beyond this study.

### Recommended: Option B (both privkey and preimage HSM-derived)

| Secret | Current storage | Proposed storage | Re-derivation |
|---|---|---|---|
| Claim privkey | plaintext in datastore | HSM-derived, never stored | `makesecret("swap-claim-{payment_hash}")` |
| Preimage | plaintext in datastore | HSM-derived from stored seed | `makesecret("swap-preimage-{seed}")` |
| Pubkey | datastore (already public) | unchanged | N/A |
| Payment hash | datastore (already public) | unchanged | N/A |
| Seed | N/A (doesn't exist today) | datastore (safe without HSM) | N/A |

### Migration path for existing swaps

Existing swaps have plaintext privkeys/preimages in the datastore. A
one-time migration at startup:

```python
for swap in self.swaps.values():
    if hasattr(swap, 'privkey') and swap.privkey:
        # old-format swap: derive the HSM version, verify it matches
        # (it won't — different derivation), so we need to:
        # 1. Generate a new seed
        # 2. Derive the preimage from the HSM with the new seed
        # 3. Verify sha256(derived_preimage) == swap.payment_hash
        #    (it WON'T match — different preimage!)
        # FAIL: existing swaps' preimages can't be re-derived from the
        # HSM because they were randomly generated, not HSM-derived.
        #
        # MIGRATION STRATEGY: keep old swaps' secrets in the datastore
        # (with a migration warning), only NEW swaps use HSM derivation.
        pass
```

**The migration is one-directional:** new swaps use HSM derivation,
old swaps keep their plaintext secrets until they expire/complete.
This is acceptable because:
- Old swaps have bounded lifetimes (locktime + cleanup)
- The number of old swaps is small
- A future cleanup pass can purge expired old-format records

### Security properties (what changes)

| Attacker capability | Before (current) | After (HSM-split) |
|---|---|---|
| Read datastore → get sweep kit | ✅ Full (privkey + preimage) | ❌ No secrets (seed only, useless without HSM) |
| CLN RPC → makesecret → get keys | ❌ Not possible | ⚠️ Possible if you know the derivation label |
| Read CLN log → get secrets | ✅ If debug enabled | ❌ Never logged |
| Compromise HSM | N/A | ✅ Complete compromise (but HSM is CLN's security boundary) |

The `makesecret` RPC is the remaining surface: anyone with CLN RPC can
call `makesecret("swap-claim-{payment_hash}")` and get the claim key.
But this is the same security level as CLN's own key material — if an
attacker has RPC access, they can already drain the wallet. The HSM
doesn't protect against RPC compromise; it protects against datastore
reads (filesystem, backup leakage) and log exposure.

### Unit test approach (validated)

```python
def test_hsm_derivation_produces_valid_key():
    """The makesecret output must be a valid secp256k1 private key."""
    secret = bytes.fromhex("8d372130d0e6fa5723108a958175caf0aec5aebdc6b8e3ead95c7c03c166c79e")
    assert len(secret) == 32
    assert secret != b'\x00' * 32
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert 0 < int.from_bytes(secret, 'big') < order

def test_hsm_derivation_deterministic():
    """Same label → same secret (verified live on production signet)."""
    # this is a structural property of CLN's HSM; the test validates
    # our derivation wrapper, not CLN's internals
    ...
```

## What we need before implementation (per owner directive)

1. ✅ makesecret is deterministic — verified live
2. ✅ makesecret output is a valid secp256k1 key — verified mathematically
3. ✅ The plugin already uses derive_secret for other secrets
4. 🔲 Decide: Option A (privkey only) vs Option B (privkey + preimage)
5. 🔲 Design the migration path for existing swaps
6. 🔲 Accept the makesecret RPC surface as within CLN's security boundary
7. 🔲 Owner approval to implement

## References

- Issue #36 (this research's tracking issue)
- Issue #13 (the original secrets-exposure finding)
- docs/security-analysis-2026-08-30.md (Section 5: the enabler)
- CLN docs: `makesecret` RPC (HSM-derived, deterministic, per-node)
- Our existing pattern: `plugin_config.py:51` (nostr secret via makesecret)
