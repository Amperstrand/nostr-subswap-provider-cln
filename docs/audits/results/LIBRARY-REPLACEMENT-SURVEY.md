# LIBRARY-REPLACEMENT-SURVEY — vendored-electrum code vs pip reality

- **Date:** 2026-08-21
- **Auditor:** opencode (ultrawork session), evidence gathered live on this box
- **Scope:** `swap-provider/plugin/` (10,636 LOC over 24 files), `cln-plugin.Dockerfile`, `swap-provider/requirements.txt`, `tests/`
- **Policy baseline** (boltz-bridge `AGENTS.md` "Library policy", applied here by the same operator):
  use established, reputable, well-tested libraries; no hand-rolled crypto/encoders/protocol
  parsing; vet candidates — major maintainer org (bitcoin-core, sipa, ACINQ, Blockstream,
  Elements, electrum) or large adopter base, years of history, visible maintenance; compare
  2–3 options before adopting. Niche single-author libs are a liability in money-handling code.
- **Method:** `wc -l` inventory; full import-graph grep of every `import`/`from` line;
  provenance headers read; sibling checkout `/home/ubuntu/src/electrum`
  (`4.8.0-142-gbbcf925cd`) diffed against vendored files; PyPI metadata verified by
  download (`pip download bitcoinrpc==0.7.0` → METADATA) and `pip3 show`; installability of
  `electrum` tested (`pip3 index versions electrum` → *No matching distribution found*).

---

## 0. Executive summary

The plugin vendors ~70% old Electrum internals. That is **not a policy violation** — it is the
only viable strategy: Electrum is the protocol reference for the clients we serve, its internals
are **not pip-installable** (verified: no `electrum` distribution on PyPI; the package
`__init__.py` imports `Wallet`/`Network`/`Daemon`/GUI plugins at import time — it is an
application, not a library), and no other pip package offers an equivalent PSBT/transaction
stack. The crypto itself is already fully delegated to vetted libraries: `electrum_ecc`
(Electrum org) for all ECDSA/secp256k1, `electrum_aionostr` (Electrum org) for all
Nostr/NIP-04, `pycryptodome` as ripemd160 fallback, and PSBT **signing is delegated to CLN
itself** (`fundpsbt`/`signpsbt`/`sendpsbt`, cln_chain.py:31–74) — the plugin never signs with
its own keys on the chain path.

The real findings are smaller and sharper:

1. **Two money-path imports survive only as transitive dependencies** — `aiorpcx`
   (utils.py:26, direct) and `httpx` (bitcoin_core_rpc.py:6, direct) are absent from
   requirements.txt and arrive only via `electrum-aionostr`'s and `bitcoinrpc`'s metadata.
   Pin them explicitly. **DO NOW.**
2. **No vendored module should be replaced by a pip package.** Every candidate fails either
   the vetting bar (lnbits/`bolt11`: 12-star repo, `click` as a lib dep; PyPI `bech32`:
   fiatjaf's repackaging of the exact sipa reference we already vendor) or the blast-radius
   test (`python-bitcoinlib` 0.11.0 has no PSBT module at all).
3. **Refresh-in-place from the electrum upstream** is the correct maintenance mode for the
   vendored set, and drift is measurable: 843 diff-lines on `transaction.py`, 186 on
   `bitcoin.py`, 37 on `bip32.py`, 30 on `segwit_addr.py` vs the 4.8 checkout.

---

## 1. Vendored-module inventory and per-module verdicts

LOC from `wc -l swap-provider/plugin/*.py` (total 10,636).

### 1.1 `transaction.py` — 2,395 LOC — **KEEP-VENDORED**

Electrum 2011 Thomas Voegtlin, "deserialization code originally comes from ABE"
(transaction.py:1–16 header). Provides `Transaction`/`PartialTransaction`: PSBT parse +
serialize, output assembly, txid, fee/weight math, input signing scaffolding.

**What the plugin actually exercises** (grep counts): `from_raw_psbt` (cln_chain.py:52,64),
`add_outputs`, `set_rbf`, `_serialize_as_base64`, `finalize_psbt`, `serialize()` (15 uses),
`.txid()` (5 uses). Key handling is structural only — the one in-file signing helper
(transaction.py:2265) already delegates DER encoding to `ecc.ecdsa_der_sig_from_r_and_s`
(electrum_ecc).

**Replacement candidates checked:**
- `python-bitcoinlib` 0.11.0 (petertodd — bitcoin-core-adjacent lineage, passes vetting):
  installed locally, module surface enumerated: `base58, bech32, bloom, core, messages, net,
  rpc, segwit_addr, signature, signmessage, wallet` — **no PSBT module**, no
  PartialTransaction equivalent. Replacing would mean reimplementing the PSBT layer on a less
  capable base.
- Full `electrum` package: **not pip-installable** (§4a).
- `hwilib` (bitcoin-core): descriptor-focused, no PSBT tx-construction seam for our flow.

**Verdict:** KEEP-VENDORED. Upstream drift 843 diff-lines vs electrum 4.8 (2,701 LOC there) —
refresh-in-place on the LATER cadence, never replace.

### 1.2 `descriptor.py` — 1,072 LOC — **KEEP-VENDORED**

Provenance header (descriptor.py:1–7): forked from **bitcoin-core/HWI** (`hwilib/descriptor.py`,
Andrew Chow 2017) as modified by Electrum 2023. Output-script descriptors; consumed by
`transaction.py` (dummy descriptors, create_dummy_descriptor_from_address —
transaction.py:52) and `bitcoin.py:395`.

**Candidates:** `hwilib` IS pip-installable and bitcoin-core-maintained — the only candidate in
the whole audit that both passes vetting and matches the file's lineage. But the vendored copy
carries Electrum's modifications for PSBT/PartialTransaction interop
(descriptor.py:33–36 imports our bip32/bitcoin/segwit_addr), and pip `hwilib` drags the whole
hardware-wallet device stack for a module whose entire runtime role here is dummy-descriptor
plumbing. Blast radius >> benefit.

**Verdict:** KEEP-VENDORED.

### 1.3 `bitcoin.py` — 849 LOC — **KEEP-VENDORED**

Electrum 2011 (header, bitcoin.py:1–4). The address/script layer: `opcodes` IntEnum (:57),
script-number/varint/push encoding (:198–315 `script_num_to_bytes`, `var_int`,
`witness_push`, `construct_script`, `construct_witness`), base58 (:513–597 — see §2),
address↔script conversion (:353–489), taproot/BIP340 helpers (:760–840).

Used directly by the swap path: `construct_script`, `construct_witness`,
`script_to_p2wsh`, `opcodes`, `dust_threshold` (submarine_swaps.py:25,29) — this builds the
HTLC redeemScript and claim witness, i.e. **the funds-critical bytes**. It is byte-for-byte
Electrum logic the Electrum clients expect (see test/swap-lifecycle fixtures in the bridge
repo annotating the 106-byte redeemScript).

**Verdict:** KEEP-VENDORED (electrum parity IS the spec here). Taproot helpers are dead weight
for P2WSH-only swaps but ride along with parity — noted, not acted on.

### 1.4 `bip32.py` — 528 LOC — **KEEP-VENDORED**

Electrum 2018 (header). `BIP32Node` xprv/xpub handling. Runtime use is PSBT-structural:
descriptor.py:33,194 and transaction.py:43,1455,1834,1902–1981 round-trip BIP32 paths inside
PSBTs CLN produces/consumes. Derivation math delegates to `electrum_ecc`
(bip32.py:10). No standalone reputable pip lib matches the electrum object model
(`python-bitcoinlib.wallet` is a different, incompatible shape). Drift 37 diff-lines vs 4.8.

**Verdict:** KEEP-VENDORED.

### 1.5 `segwit_addr.py` — 159 LOC — **KEEP-VENDORED**

Pieter Wuille's reference implementation (license header, segwit_addr.py:1–5) via Electrum —
bech32/bech32m + segwit addresses. This is already *the* canonical sipa code; the diff vs the
4.8 checkout is 30 lines of cosmetics (upstream added an `INVALID_BECH32` sentinel and a
`with_checksum` kwarg we don't need). The PyPI `bech32` 1.2.0 package (pip show: Home-page
github.com/fiatjaf/bech32) is a third-party repackaging of the same reference — swapping
gains nothing and adds a supply-chain hop.

**Verdict:** KEEP-VENDORED.

### 1.6 `lnaddr.py` — 569 LOC — **KEEP-VENDORED (refresh candidate, §4b)**

Fork of **rustyrussell/lightning-payencode @acc16ec** (lnaddr.py:1) — Rusty Russell is
CLN's author, so the lineage is as reputable as this code family gets. BOLT #11
encode/decode: `lnencode_unsigned` (:157), `LnAddr` (:256), `lndecode` (:388).

Plugin-specific divergence (git log): `lnencode_unsigned` appends a 104-byte dummy signature
(lnaddr.py:234–236) so CLN's `signinvoice` RPC accepts and re-signs the string
(cln_lightning.py:517–525) — the plugin deliberately never holds the node key.
Readers of untrusted invoices (`invoices.py:441,519,530`) are pinned by
AUDIT-1/AUDIT-2, specquotes.toml, and byte-level regression tests
(tests/test_e2e_bug_regressions.py:240–267).

**Verdict:** KEEP-VENDORED — full analysis in §4.

### 1.7 `json_db.py` (424), `utils.py` (521), `lnutil.py` (141), `constants.py` (210), `invoices.py` (547), `crypto.py` (63) — **KEEP-VENDORED / KEEP**

All Electrum-origin glue, none of it crypto:

- `crypto.py` — thin hashlib/hmac wrappers; `ripemd` uses `hashlib` with pycryptodome
  fallback (crypto.py:48–59, the already-completed fix).
- `utils.py` — electrum util grab-bag: `descsum_create` descriptor checksum
  (utils.py:47–80, bitcoin-core algorithm), `ShortID`, `OldTaskGroup(aiorpcx.TaskGroup)`
  (:454), `format_satoshis`. Hand-rolled but algorithmically trivial, test-covered,
  electrum-parity.
- `lnutil.py` — stripped electrum `LnFeatures` bitflags + hex helpers; plugin's
  nostr `Keypair` wraps `electrum_ecc` (plugin_config.py:23 uses a key derived via CLN
  `derive_secret("NOSTRSECRET")`, plugin_config.py:42).
- `invoices.py` — electrum invoice model reworked around CLN hold-invoices
  (`HoldInvoice`, cln_lightning.py:20); not replaceable by anything on PyPI.
- `json_db.py` — electrum's JsonDB over `jsonpatch` (proper dep, requirements.txt:5).

### 1.8 Plugin-authored (not vendored, listed for completeness)

`cln_plugin.py` 80, `cln_logger.py` 77, `cln_storage.py` 102, `cln_swap_provider.py` 100,
`chain_monitor.py` 51, `globals.py` 9 — glue over `pyln-client` (Elements, requirements.txt:1).
`cln_chain.py` 145 — CLN wallet RPC (fundpsbt/signpsbt/sendpsbt). `cln_lightning.py` 643 —
CLN hold-invoice lifecycle. `plugin_config.py` 207 — env config + offer PoW wiring.
`bitcoin_core_rpc.py` 453 — bitcoind RPC via the `bitcoinrpc` package (§3).
`submarine_swaps.py` 1,209 — the port itself (electrum 4.8.1 SwapManager + NostrTransport);
this IS the product, not a vendoring. `offer.py` 82 — §4c.

---

## 2. Hand-rolled code with a vetted-library equivalent anywhere

| Hand-rolled | Location | Vetted pip candidate | Reputable? | Swap worth it? |
|---|---|---|---|---|
| base58/base58check | bitcoin.py:513–597 (`base_encode`, `base_decode`, `EncodeBase58Check`, `DecodeBase58Check`) | `python-bitcoinlib.base58` (petertodd); `base58` PyPI (keis) | petertodd yes; keis single-author but huge adopter base | **No** — used by bip32.py:15, lnaddr.py:13 fallback-address encoding; 85 lines of 10-year-stable electrum code, byte-parity matters, seam touches xprv parsing in money path |
| bech32/bech32m | segwit_addr.py (whole file) | `bech32` PyPI 1.2.0 (fiatjaf's packaging of sipa ref) | code is sipa's; packaging is third-party | **No** — identical reference code already vendored; PyPI adds a hop, zero delta |
| BOLT #11 encode/decode | lnaddr.py (whole file) | `bolt11` PyPI 2.2.0 (lnbits) | fails bar — see §4b | **No** |
| output-descriptor parsing | descriptor.py | `hwilib` (bitcoin-core) | yes | **No** — §1.2 (device-stack drag + interop rework) |
| DER/ECDSA signing | — | `electrum_ecc` already in use | yes | already done: transaction.py:2265 delegates to `ecc.ecdsa_der_sig_from_r_and_s`; bitcoin.py:846–849 delegates to `ec_privkey.ecdsa_sign_recoverable`; swap-key ops are `ECPrivkey` (submarine_swaps.py:16,541,639,735). **Nothing hand-rolled remains on any signing path** — chain signing is CLN's `signpsbt` (cln_chain.py:59) |
| BIP340/taproot tweak+tagged hash | bitcoin.py:760–840 | electrum_ecc does not expose schnorr; no vetted pip candidate | — | **Won't act** — dead code for P2WSH-only swaps, carried for electrum parity of bitcoin.py/descriptor.py. Keep an eye on it: never let the swap path grow a taproot dependency without revisiting |
| descriptor checksum (descsum) | utils.py:47–80 | none reputable standalone | — | keep; ~30 lines, bitcoin-core algorithm, unit-tested |
| Nostr PoW mining | offer.py:23–52 | none (nor should there be — §4c) | — | keep |

Grep-verified that the repo imports **none** of the dev-image extras (`bitcoinlib`,
`coincurve`, `bolt11`, `bech32`, `base58`): zero hit count across `swap-provider/` and
`tests/` — those pip entries are dev-box noise from other projects, not plugin deps.

---

## 3. Dockerfile / requirements vs actual imports

**Installed by the image** (cln-plugin.Dockerfile:6–19): base
`elementsproject/lightningd:v26.06` (Elements — carries a matching `pyln-client`), apt
`libsecp256k1-dev` + `ELECTRUM_ECC_DONT_COMPILE=1` (:14) so electrum_ecc binds the system
libsecp256k1 instead of compiling its bundled one, then `pip3 install -r requirements.txt`:

| requirements.txt line | pin | imported where | status |
|---|---|---|---|
| `pyln-client` :1 | >=26,<27 | cln_plugin.py:3–4, cln_chain.py:4 | explicit ✓ |
| `electrum-aionostr` :2 | >=0.1,<0.2 | submarine_swaps.py:15,22; plugin_config.py:4 | explicit ✓ — same window electrum itself pins (`contrib/requirements/requirements.txt:9` in the sibling checkout) |
| `electrum-ecc` :3 | >=0.0.4,<0.1 | bip32.py:10, bitcoin.py:30, descriptor.py:31, lnaddr.py:11, lnutil.py:6, transaction.py:40, submarine_swaps.py:16 | explicit ✓ |
| `attrs` :4 | >=24.2,<26 | invoices.py:1, lnutil.py:5, plugin_config.py:1, submarine_swaps.py:7, bitcoin_core_rpc.py:3 | explicit ✓ |
| `jsonpatch` :5 | >=1.33,<2 | json_db.py:28 | explicit ✓ |
| `python-dotenv` :6 | >=1.0.1,<2 | plugin_config.py:5 | explicit ✓ |
| `pycryptodome` :7 | >=3.20 | crypto.py:58 (fallback) | explicit ✓ |
| `bitcoinrpc` :8 | >=0.7,<0.8 | bitcoin_core_rpc.py:4 | explicit ✓ — see policy note below |

**Gaps — directly-imported but only transitively satisfied:**

| import | site | arrives via | risk |
|---|---|---|---|
| `aiorpcx` | utils.py:26 (module level: `OldTaskGroup(aiorpcx.TaskGroup)`) | electrum-aionostr's Requires | if aionostr ever drops/switches it, the whole plugin fails at import |
| `httpx` | bitcoin_core_rpc.py:6 (`from httpx import Timeout`) | bitcoinrpc's `Requires-Dist: httpx <1` (verified from the 0.7.0 wheel METADATA) | same class; also silently caps httpx major version without us recording why |

Lazy `import aiohttp` at bitcoin_core_rpc.py:194 is also aionostr-covered. `orjson`/
`typing-extensions` (bitcoinrpc's other requires) are not imported directly — fine.

**Fix (DO NOW):** add `aiorpcx>=0.25,<0.26` and `httpx>=0.25,<1` to requirements.txt.

**Policy notes on existing deps:**
- `bitcoinrpc` 0.7.0 (wheel METADATA: author Libor Martinek,
  github.com/bibajz/bitcoin-python-async-rpc) is a single-author async fork of jgarzik's
  python-bitcoinrpc. That is a genuine policy tension in the chain-monitoring path (it reads
  lockup TXs; writes go through CLN's `sendpsbt`/`sendrawtransaction` paths, not here). It is
  small, httpx-based, and read-mostly for us; the electrum-side equivalent
  (`electrum.network` JsonRPCClient) is even less installable. Keep, re-vet if it ever needs
  to broadcast.
- Dev-box parity gap: `bitcoinrpc` is **not installed in this dev environment**
  (`ModuleNotFoundError: No module 'bitcoinrpc'`) while it is required at
  bitcoin_core_rpc.py:4 — any local test importing that module needs the Docker image or a
  `pip install -r swap-provider/requirements.txt` in the dev venv.

---

## 4. Specific assessments

### (a) Could lnaddr.py be replaced by importing from a vendored full-electrum checkout? — **NO**

Documented reasons, all verified on the box:

1. **`electrum` is not a pip library.** `pip3 index versions electrum` → *No matching
   distribution found*; `pip3 download electrum` → same error. There is no supported
   distribution; consuming it means vendoring a checkout and sys.path tricks.
2. **The package `__init__` is the whole application.** `electrum/__init__.py` (sibling
   checkout, 4.8.0-142) executes `from .wallet import Wallet`, `from .network import Network`,
   `from .daemon import …`, `from .commands import Commands`, GUI plugin machinery — importing
   `electrum.bolt11` transitively boots wallet/daemon/network code and its full dependency
   tree (aiohttp, aiorpcx, protobuf, qrcode, …). That is a runtime and attack surface we
   will not put in a money-path plugin.
3. **Relative-import coupling.** upstream renamed the file `lnaddr.py` → `bolt11.py` in 4.8
   and it does `from .bitcoin import …`, `from .segwit_addr import …`,
   `from .constants import AbstractNet` (bolt11.py:15–20) — it cannot be lifted without the
   package context, i.e. exactly the vendoring-and-stripping we already did once.
4. **Our fork is deliberately diverged for CLN**: `lnencode_unsigned` + 104-byte dummy
   signature (lnaddr.py:234–236) exists because signing happens in CLN via `signinvoice`
   (cln_lightning.py:520–525). Upstream signs in-process with the node key — a flow this
   plugin must not use.

Net: vendoring-and-stripping (current approach) *is* the import-from-electrum strategy, done
with a scalpel instead of a forklift.

### (b) Is there a maintained bolt11 encoder lib worth porting to? — **NO (bar not met)**

Compared the 2–3 options per policy:

1. **rustyrussell/lightning-payencode** (what we forked, @acc16ec, lnaddr.py:1): last push
   **2023-05-18** — dormant 3+ years. Lineage perfect (CLN author), maintenance dead.
2. **`bolt11` on PyPI 2.2.0** (lnbits/bolt11): actively released (2.2.0 2026-01-28) and
   honest about lineage ("based on previous work by Rusty Russell, the Electrum Wallet team,
   and the LNbits bolt11 helpers by @fiatjaf"). But: repo has **12 stars**, and its dependency
   set (`Requires: base58, bech32, bitstring, click, coincurve`) includes `click` — a CLI
   framework as a library dep — and `coincurve`, which would sit next to electrum_ecc as a
   second, redundant secp256k1 binding. Per the policy's own bar (major org **or large
   adopter base**), this is a niche small-adopter repo in the invoice-creation money path.
3. **electrum's own `bolt11.py`**: not a lib (see (a)) — but it is the *parity reference*,
   which matters more here than anywhere else: our invoices are consumed by Electrum clients,
   and the swap-protocol audits (AUDIT-1/2, specquotes.toml) pin our reader to electrum's
   byte-level behavior.

Additional friction: the `bolt11` lib's API signs internally; it has no
"encode-unsigned-then-hand-to-CLN-signinvoice" seam, so adopting it would force the plugin to
hold the node key or restructure the signing flow. **Verdict: stay vendored; refresh from
upstream electrum instead (LATER).**

### (c) Nostr — is anything still hand-rolled?

- **NIP-04 encryption/decryption:** library — `aionostr.key.PrivateKey.encrypt_message` /
   `decrypt_message` (submarine_swaps.py:1133 and 1202). No hand-rolled NIP-04 anywhere.
- **Event construction/publishing:** library — `aionostr._add_event` with explicit kind 25582
   and p-tags (submarine_swaps.py:1112, 1203–1208; the explicit-kind dance is PORT FIND #8,
   documented in-source). NIP-19 key encoding: `aionostr.util.to_nip19/from_nip19`
   (submarine_swaps.py:22,1201).
- **Offer PoW (offer.py:23–52):** hand-rolled **by design** — it must reproduce Electrum's
  exact announcement PoW (`sha256(b"electrum-" || pubkey || nonce_be32)`, leading zero bits),
  cross-checked against electrum.util.get_nostr_ann_pow_amount (offer.py:23–37). This is
  protocol parity logic, not crypto primitive invention; a "library" cannot replace it
  without breaking client discovery. The heavy-mining path is external
  (scripts/mine-nonce.sh + the nostr-pow-bench tooling noted at offer.py:42–44).
- **Offer wire format (offer.py:55–82):** electrum 4.8.1 byte-parity (NOSTR_EVENT_VERSION 5,
  d/r/expiration tags) — same parity argument.

**Conclusion: nothing nostr remains hand-rolled except electrum-parity logic that must stay.**
(NIP-04 itself is deprecated nostr-wide but is what Electrum clients speak — compat trumps
modernity; revisit only if electrum clients migrate, at which point electrum_aionostr's
successor moves with them.)

---

## 5. Prioritized action table

| # | Action | Priority | Rationale |
|---|---|---|---|
| 1 | Add explicit pins `aiorpcx>=0.25,<0.26` and `httpx>=0.25,<1` to swap-provider/requirements.txt | **DO NOW** | Directly imported at utils.py:26 / bitcoin_core_rpc.py:6 but only transitively declared — accidental-deletion-class fragility in the money path (§3) |
| 2 | Install requirements.txt in the dev venv (or conftest stub for `bitcoinrpc`) so local pytest can import bitcoin_core_rpc.py:4 | **DO NOW** | dev/image parity; currently ModuleNotFoundError locally |
| 3 | REFRESH-IN-PLACE lnaddr.py from sibling electrum `bolt11.py` (4.8): exception renames, spec-wording corrections, `bech32_decode` `with_checksum` param — keeping `lnencode_unsigned` + dummy-sig seam | **LATER** | Drift is small and fully test-pinned (AUDIT-1/2, specquotes, test_e2e_bug_regressions.py:240–267); refresh buys upstream fixes without policy risk |
| 4 | Same refresh cadence for segwit_addr.py (30 diff-lines), bip32.py (37), bitcoin.py (186), transaction.py (843) — refresh from electrum upstream, never replace | **LATER** | Electrum remains the de-facto spec for client compat; measure drift each refresh (§0.3) |
| 5 | Re-vet `bitcoinrpc` if its role ever expands past read-mostly chain queries | **LATER** | Single-author lib (jgarzik lineage) tolerated as accepted dep; policy tension documented in §3 |
| 6 | Replace `transaction.py`/`bitcoin.py`/`bip32.py` with python-bitcoinlib | **WON'T DO** | 0.11.0 has no PSBT module (verified); loses electrum byte-parity; seam-wide rewrite of the funds path |
| 7 | Replace `lnaddr.py` with PyPI `bolt11` (lnbits) | **WON'T DO** | Fails vetting bar (12-star repo, click dep, second secp256k1 binding); no unsigned-encode seam for CLN signinvoice; loses electrum parity (§4b) |
| 8 | Replace `segwit_addr.py` with PyPI `bech32` | **WON'T DO** | Same sipa reference code we already vendor; swap is a pure supply-chain hop (§1.5) |
| 9 | Import bolt11/transaction from a vendored full-electrum checkout | **WON'T DO** | Not on PyPI; app-level `__init__` boots wallet/network/daemon; relative-import coupling; our deliberate CLN divergences (§4a) |
| 10 | Replace offer.py PoW / wire format with a nostr library | **WON'T DO** | Electrum client discovery depends on byte-exact parity (§4c) |
| 11 | Swap electrum_ecc → coincurve (or secp256k1-py) | **WON'T DO** | Redundant second binding; electrum_ecc is the electrum-org choice, ctypes over the same libsecp256k1 the image already ships (Dockerfile:9–14) |

---

## Appendix — evidence commands (reproducible)

```
wc -l swap-provider/plugin/*.py                                  # inventory + LOC
grep -n "^import \|^from \|    import \|    from " swap-provider/plugin/*.py   # import graph
cat cln-plugin.Dockerfile swap-provider/requirements.txt
pip3 list | grep -iE "electrum|pyln|coincurve|bitcoinlib|bolt11|bech32|aiorpcx|httpx"
pip3 download bitcoinrpc==0.7.0 --no-deps -d /tmp/… && unzip -p … METADATA   # httpx/orjson transitives
pip3 index versions electrum                                     # → No matching distribution found
python3 -c "import pkgutil, bitcoin; print([m.name for m in pkgutil.iter_modules(bitcoin.__path__)])"
diff /home/ubuntu/src/electrum/electrum/<mod>.py swap-provider/plugin/<mod>.py | wc -l   # drift
git -C . log --oneline --follow -- swap-provider/plugin/lnaddr.py
```

External checks (web): rustyrussell/lightning-payencode last push 2023-05-18;
pypi.org/project/bolt11 version history through 2.2.0 (2026-01-28), lnbits/bolt11 repo
(12 stars), requires base58/bech32/bitstring/click/coincurve; PyPI `bech32` 1.2.0 =
github.com/fiatjaf/bech32 packaging of the sipa reference.
