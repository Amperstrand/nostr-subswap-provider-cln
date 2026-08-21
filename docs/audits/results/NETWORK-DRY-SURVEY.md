# NETWORK-DRY-SURVEY: Network-Conditional Code & Config Across regtest / signet / mutinynet

- **Date:** 2026-08-21
- **Repo commit audited:** `94ac0cd58e9b04de6ad61338dd18d9a977363b18` (`94ac0cd fix(#2,#3): audit P0s — guarded preimage extraction + prepay-expiry teardown`)
- **Scope:** every code path that branches on network, in this repo and in the three deployments (regtest lab, inr2 signet, inr2 mutinynet). Deployment inventory documents knobs only — no lightning-playground changes proposed.
- **Method:** full read of `constants.py`, `plugin_config.py`, `offer.py` (+ grep of every `constants.net` / `NET_NAME` / `BOLT11_HRP` / `SEGWIT_HRP` / network-string consumer), `bitcoin_core_rpc.py`, `cln_chain.py` network conditionals, all net-touching tests; live read of the inr2 compose files and on-box lightning/bitcoin configs over ssh (`inr2.cashu.exchange`, 2026-08-21); `git log -S` for class history. Verification run this session: `pytest tests/test_plugin_config_pow.py tests/test_protocol_contract.py` → **11/11 passed**.
- **Record correction:** the task brief mentioned a `SignetRegtest` class; `git log --all -S "SignetRegtest"` finds nothing — it never existed in history. The signet-genesis-shared class is **`BitcoinMutinynet`**, added in `8c12e27` together with `ANN_NET_NAME`.

---

## 1. Code-side map

### 1.1 Net classes — `swap-provider/plugin/constants.py`

Port of electrum's constants module. Class hierarchy (verbatim fields that matter here):

| Class | Lines | NET_NAME | SEGWIT_HRP | BOLT11_HRP | GENESIS | Parent |
|---|---|---|---|---|---|---|
| `AbstractNet` | 49–82 | *(declared, :51)* | *(declared, :56)* | *(declared, :57)* | *(declared, :58)* | — |
| `BitcoinMainnet` | 85–120 | `"mainnet"` :87 | `"bc"` :92 | `=SEGWIT_HRP` :93 | mainnet hash :94 | AbstractNet |
| `BitcoinTestnet` | 123–156 | `"testnet"` :125 | `"tb"` :130 | `=SEGWIT_HRP` :131 | testnet hash :132 | AbstractNet |
| `BitcoinTestnet4` | 159–163 | `"testnet4"` :161 | `tb` (inherited) | `tb` (inherited) | testnet4 hash :162 | BitcoinTestnet |
| `BitcoinRegtest` | 166–173 | `"regtest"` :168 | `"bcrt"` :169 | `=SEGWIT_HRP` :170 | regtest hash :171 | BitcoinTestnet |
| `BitcoinSimnet` | 176–186 | `"simnet"` :178 | `"sb"` :182 | `=SEGWIT_HRP` :183 | simnet hash :184 | BitcoinTestnet |
| `BitcoinSignet` | 189–195 | `"signet"` :191 | `tb` (inherited) | **`"tbs"`** :192 | signet hash :193 | BitcoinTestnet |
| `BitcoinMutinynet` | 198–204 | `"mutinynet"` :200 | `tb` (inherited) | **`"tbs"`** :201 | **same hash as signet** :202 | BitcoinTestnet |

Key machinery:

- `NETS_LIST = tuple(all_subclasses(AbstractNet))` — constants.py:207. **Auto-extends**: any new class is picked up with zero registry edits (`all_subclasses` at utils.py:85–90 walks transitively).
- Module-global singleton `net = BitcoinMainnet` — constants.py:210, with the comment "don't import net directly, import the module instead".
- `AbstractNet.set_as_network()` — constants.py:79–82. **Dead code in this repo**: grep finds no caller; the one writer is `plugin_config.py:46`.

### 1.2 The global `net` lifecycle — single write, ~21 read sites

**Write (exactly one):**

- `plugin_config.py:26` — `self.network = self.__parse_network_type(cln_configuration["network"]["value_str"])` (parses CLN's `listconfigs` `network` value).
- `plugin_config.py:46` — `constants.net = config.network`, once at startup inside `PluginConfig.from_cln_and_env`.

**Read sites (all resolve at call time via `constants.net`, never cached):**

| File | Lines | What it gates |
|---|---|---|
| `bitcoin.py` | 368, 372, 379–380, 423–426, 454–457, 676–678, 684–686, 692 | `net=None` defaults → address encode/decode via `net.SEGWIT_HRP` |
| `bitcoin.py` | 608, 610, 637, 644 | WIF key prefix (`net.WIF_PREFIX`) |
| `bip32.py` | 107, 113, 137 | xprv/xpub serialization headers |
| `lnaddr.py` | 266, 393, 407–408, 421 | BOLT11 HRP encode/decode (`net.BOLT11_HRP`) |
| `descriptor.py` | 1058, 1062, 1064 | address→descriptor parsing (`SEGWIT_HRP`, `ADDRTYPE_*`) |

Plus two consumers of the **instance** `config.network` (not the global): `submarine_swaps.py:611` and `:674` (`script_to_p2wsh(redeem_script, net=self.config.network)` — lockup addresses) and `cln_lightning.py:504` (`LnAddr(net=self._config.network, …)` — invoice HRP).

This is the DRR win of the design: one assignment point, everything downstream keys off `constants.net` / the config instance. No per-network branching exists in any swap logic.

### 1.3 Network parsing and the nostr `net:` tag — `plugin_config.py` + `offer.py`

- `__parse_network_type` — plugin_config.py:160–171. Hand-rolled if/elif over the **CLN string**: `"mainnet" | "testnet" | "signet" | "regtest"` → instantiated class; anything else raises `Invalid network type`. Note: accepts no `testnet4`, no `simnet`, no `mutinynet`, and **not `"bitcoin"`** — see inconsistency I1.
- `config.net_name = config.network.NET_NAME` — plugin_config.py:76.
- `ANN_NET_NAME` override — plugin_config.py:81–88: if set, must match some `NET_NAME` in `NETS_LIST` (fail-loud at :83–87 with the full valid list in the error), then `config.net_name = ann_net`. The comment at :77–80 documents the rationale: mutinynet nodes run CLN `network=signet` (shared genesis) yet must announce `net:mutinynet` because the tag is the only wrong-network discriminator clients (electrum, bridge worker) have.
- Tag construction — `offer.py:74–81`, `build_offer_tags(net_name)` emits `["r", f"net:{net_name}"]` (:80). Pure function; the only production caller is `submarine_swaps.py:1111` (`publish_offer`), which passes `self.config.net_name`.

So the ANN_NET_NAME resolution is already a **single point**: one resolver (plugin_config.py:76–88), one consumer (submarine_swaps.py:1111), one wire builder (offer.py:80).

### 1.4 String-keyed network conditionals (parallel to the net-class system)

These branch on the raw CLN network string, not on `AbstractNet`:

| File:line | Conditional | Purpose |
|---|---|---|
| `bitcoin_core_rpc.py:27` | `self._network = bcore_rpc_credentials.network` | stores the CLN string |
| `bitcoin_core_rpc.py:130` | `if self._network != "regtest" and blockheader["time"] < time.time() - 3600` | tip-freshness gate; regtest exempted because lab chains idle (port find #3, comment :127–129) |
| `bitcoin_core_rpc.py:395` | `_NETWORK_DEFAULT_RPCPORT = {"bitcoin": 8332, "testnet": 18332, "signet": 38332, "regtest": 18443}` | per-network rpcport default when CLN ≥24.11 omits `bitcoin-rpcport` (comment :391–393) |
| `bitcoin_core_rpc.py:403` | `network = cln_config.get("network", {}).get("value_str", "bitcoin")` | defaults the CLN string to **"bitcoin"** |
| `cln_chain.py:98` | `if response['network'] == 'bitcoin': assert blockheight > 869000` | mainnet-only blockheight sanity floor (skipped on all our nets) |

### 1.5 Tests that pin or monkeypatch networks

| File:lines | What it does |
|---|---|
| `tests/test_plugin_config_pow.py:62–70` | `_StubCLN.fetch_cln_configuration` returns `{"network": {"value_str": "regtest"}}` — the CLN contract stub |
| `:86–96` | `test_net_name_defaults_to_cln_network` — no `ANN_NET_NAME` → `cfg.net_name == "regtest"` |
| `:99–115` | `test_ann_net_name_overrides_cln_network` — `ANN_NET_NAME=mutinynet` → tag `net:mutinynet` while `cfg.network.NET_NAME` stays the CLN side ("regtest" in the stub) — pins the decoupling |
| `:118–128` | `test_ann_net_name_unknown_fails_loud` — garbage `ANN_NET_NAME` raises |
| `tests/test_e2e_bug_regressions.py:246–248, 282` | save → `plugin_constants.net = BitcoinSignet()` → restore around a route-hint serialization round-trip (needs HRP `lntbs`) |
| `tests/test_tombstone.py:47` | `config.network = "signet"` — assigns a **plain string** to a MagicMock config; works only because nothing in that path dereferences net fields (see I6) |
| `tests/test_protocol_contract.py:88` | `build_offer_tags("regtest", now=…)` — pure-function pin |
| `tests/tests_cln_lightning.py:18` | commented-out `# config.network = "testnet"` (dead comment) |

---

## 2. Deployment-side map (documented, no changes proposed)

### 2.1 This repo's image — `cln-plugin.Dockerfile`

**Network-agnostic.** `FROM elementsproject/lightningd:v26.06` (:6), installs python deps, `COPY swap-provider /opt/swap-provider` (:19). No network baked in — the same `lab-cln-subswap:latest` image serves **all three** networks (regtest lab, signet, mutinynet). Built by `lightning-playground docker/subswap/build.sh` (build context = this repo, tags `lab-cln-subswap:latest`).

### 2.2 regtest lab — `lightning-playground docker/docker-compose.regtest.subswap.yml`

CLN flags: `--network=regtest` (:19), `--plugin=/opt/swap-provider/swap-provider.py` (:29). Plugin env (:30–42): `NOSTR_SECRET_HEX` (stable lab identity), `NOSTR_RELAYS=ws://relay:7777`, `SWAP_FEE_PPM=5000`, `ANN_POW_TARGET_BITS=16` (in-process mining), `PLUGIN_LOG_LEVEL=DEBUG`, `CHAIN_LOOKUP_MODE=esplora`, `ESPLORA_URLS=http://mempool-shim:8788`. **No `ANN_NET_NAME`** → tag defaults to `net:regtest`.

### 2.3 signet — inr2 box `/opt/inr2-swapnet/deploy/docker-compose.yml`, mirrored at `lightning-playground docker/inr2-swapnet/docker-compose.yml`

`cln-swap` service (mirror :59–83): image `lab-cln-subswap:latest`; on-box `lightning-config` has `network=signet`, rpc → local `bitcoind` :18444, clnrest :3011. Plugin env (mirror :68–77): `NOSTR_RELAYS` (nos.lol, primal, damus), `SWAP_FEE_PPM=2000`, `ANN_POW_TARGET_BITS=30` **+ pinned `ANN_POW_NONCE=0x84a7535`** (30-bit target requires a pinned nonce — plugin_config.py:71–75), `MAX_SWAP_AMOUNT=500000`, `CHAIN_LOOKUP_MODE=esplora`, `ESPLORA_URLS=https://mempool.space/signet/api`, `LIGHTNINGD_NETWORK=signet`. **No `ANN_NET_NAME`** → `net:signet`. Port `9737:9735`. bitcoind: `lncm/bitcoind:v25.1`, plain `[signet]` conf, prune=550, mem 800m.

### 2.4 mutinynet — inr2 box `/opt/inr2-swapnet/deploy/docker-compose.mutinynet.yml` (**box-only; not mirrored in the playground repo** — see I7)

- bitcoind (:9–18): `coinswap/bitcoin-mutinynet:latest` (Inquisition v29.1 fork), `-signet`; on-box bitcoin.conf: distinct `signetchallenge=…`, **`signetblocktime=30`** (consensus input — without it the fork stalls, per boltz-bridge AGENTS.md 2026-08-21), `prune=550`, rpcport 18544, mem 1200m (index needs ≥1200m).
- `cln-swap-mutinynet` (:100–130): **same `lab-cln-subswap:latest` image**; on-box `lightning-config` has **`network=signet`** (CLN unpatched — mutinynet shares signet genesis & chain name), rpc → `bitcoind-mutinynet` :18544, clnrest :3011 published as `127.0.0.1:3013:3011` (:123). Env (:109–120): same 3 relays, `SWAP_FEE_PPM=2000`, **`ANN_POW_TARGET_BITS=20` (in-process, no pinned nonce)**, **`ANN_NET_NAME=mutinynet`** (:113), `FALLBACK_FEE_SATVB=10`, `CONFIRMATION_TARGET_BLOCKS=3`, `MAX_SWAP_AMOUNT=500000`, `CHAIN_LOOKUP_MODE=esplora`, **`ESPLORA_URLS=https://mutinynet.com/api`**, `LIGHTNINGD_NETWORK=signet`, plus `--developer` flag (:108). Ports `39737:9735` (:122).
- `electrum-swap-mutinynet` (:52–78) is profile `deferred` (public electrum server can't handshake); `cln-hub-mutinynet` (:26–49) is the client-side hub on :3012.

### 2.5 Env-knob diff, side by side (cln-swap services only)

| Knob | regtest lab | signet | mutinynet |
|---|---|---|---|
| CLN network | `--network=regtest` (flag) | `network=signet` (conf) | `network=signet` (conf, shared-genesis) |
| `ANN_NET_NAME` | — (→ regtest) | — (→ signet) | `mutinynet` |
| `ANN_POW_TARGET_BITS` | 16 (in-process) | 30 + pinned `ANN_POW_NONCE` | 20 (in-process) |
| `NOSTR_SECRET_HEX` | pinned (stable lab npub) | — (derived from HSM) | — (derived from HSM) |
| `NOSTR_RELAYS` | `ws://relay:7777` (lab strfry) | nos.lol, primal, damus | same 3 as signet |
| `ESPLORA_URLS` | `http://mempool-shim:8788` | mempool.space/signet | mutinynet.com/api |
| `SWAP_FEE_PPM` / `MAX_SWAP_AMOUNT` | 5000 / — | 2000 / 500000 | 2000 / 500000 |
| `FALLBACK_FEE_SATVB` / `CONFIRMATION_TARGET_BLOCKS` | — / — | — / — | 10 / 3 |
| LN port | 9735 (internal) | 9737 | 39737 |

*(rpc credentials exist on-box for both inr2 stacks; redacted here on purpose.)*

---

## 3. Findings

### (a) Duplicated logic that could collapse

- **D1 — `BitcoinMutinynet` body is a verbatim copy of `BitcoinSignet`** except `NET_NAME` (constants.py:189–195 vs :198–204: same inherited parent, same `BOLT11_HRP="tbs"`, same GENESIS, same `CHECKPOINTS=[]`, same `LN_DNS_SEEDS=[]`). The file's own idiom for this is subclassing: `BitcoinTestnet4(BitcoinTestnet)` overrides only `NET_NAME`/`GENESIS` (:159–163). `class BitcoinMutinynet(BitcoinSignet): NET_NAME = "mutinynet"` is behavior-identical.
- **D2 — `__parse_network_type` if/elif duplicates knowledge `NETS_LIST` already encodes** (plugin_config.py:160–171 vs constants.py:207). A `{n.NET_NAME: n for n in NETS_LIST}` lookup would collapse 4 branches and drop the import line (:13) to just `NETS_LIST`. Caveats that make this not-free: the mainnet name mismatch (I1) and that it would newly *accept* `testnet4`/`simnet`/`mutinynet` strings that currently raise (a behavior change, arguably the correct one — but a change).
- **D3 — two parallel network-keying systems**: the `AbstractNet` class graph vs the raw CLN string (`bitcoin_core_rpc.py:27/130/395/403`, `cln_chain.py:98`). They encode overlapping-but-different knowledge (the rpcport map knows `"bitcoin"`, the parser knows `"mainnet"`). Both are small; unifying them would be a bigger diff than the duplication costs.

### (b) Adding a 4th network — touch counts (verified against code)

**Path A: genesis-shared variant (the mutinynet recipe)** — CLN keeps reporting an existing network:

1. `constants.py` — add the class (mandatory: without it `ANN_NET_NAME` validation fails at startup, plugin_config.py:83–87);
2. deployment only — fork bitcoind conf (`signetchallenge`, `signetblocktime`), CLN `network=<shared>`, plugin env (`ANN_NET_NAME`, `ESPLORA_URLS`, `ANN_POW_*`);
3. consumers outside this repo (electrum client net registry, bridge-worker net-tag filter) — their own registries.

→ **1 code file / 1 class; everything else is env.** `NETS_LIST` and the `ANN_NET_NAME` valid-list auto-extend.

**Path B: genuinely new CLN `network=` value:**

1. `constants.py` — new class (NET_NAME/HRPs/GENESIS at minimum);
2. `plugin_config.py:13` — import it;
3. `plugin_config.py:160–171` — new parse branch;
4. `bitcoin_core_rpc.py:395` — `_NETWORK_DEFAULT_RPCPORT` entry (conditional: only if the default port ≠ 8332 **and** CLN omits `bitcoin-rpcport` from listconfigs);
5. deployment env/conf (as Path A minus `ANN_NET_NAME`);
6. optional but cheap: extend `test_plugin_config_pow.py` stub coverage.

→ **2 files, 3 mandatory + 1 conditional code edits; no swap-logic files.** The `constants.net` read sites (~21, §1.2) need zero edits — that's the payoff of the singleton design.

### (c) Inconsistencies between the three networks' handling

- **I1 (latent, mainnet-only): `__parse_network_type` expects `"mainnet"` but CLN reports `network=bitcoin` on mainnet.** Evidence: `bitcoin_core_rpc.py:403` defaults the same `listconfigs` field to `"bitcoin"`, and the rpcport map keys mainnet as `"bitcoin"` (:395) — two modules, two names for the same value. A mainnet node would die at plugin_config.py:170–171 with `Invalid network type: bitcoin`. Harmless today (plugin is signet/mutinynet/regtest-only; README marks mainnet reckless) but it must be fixed before any mainnet attempt.
- **I2: freshness gate keys on the CLN string, mutinynet inherits signet's rule.** `bitcoin_core_rpc.py:130` exempts only `"regtest"`. Mutinynet (`network=signet`) gets the 1-hour tip-freshness gate — correct in practice (30s blocks), and it would catch a stalled fork chain. But a hypothetical idle lab chain reusing another network name would deadlock startup sync (the regtest exemption exists precisely because of that, :127–129). Documented trap, no action needed.
- **I3: `ANN_NET_NAME` validation accepts every `NETS_LIST` name** — `mainnet`, `testnet4`, `simnet` included (constants.py:207 → plugin_config.py:83). You can announce `net:simnet` from a signet node. This is by design (the tag is a discriminator, not a chain proof) and the fail-loud list at least guarantees the tag is *unambiguous*; noting so nobody "hardens" it into an accident later.
- **I4: `_NETWORK_DEFAULT_RPCPORT` has no `mutinynet` key** — correct while CLN reports `signet` for mutinynet (→ 38332… except both inr2 stacks pin `bitcoin-rpcport` in their lightning-configs anyway, so the map is only a missing-config fallback). If CLN ever grows native `network=mutinynet`, the map would silently fall back to 8332. Comment-only concern.
- **I5: `constants.net` holds an *instance* in production but a *class* at import time.** `__parse_network_type` returns `BitcoinSignet()` etc. (plugin_config.py:163–169) while the module default is the class `BitcoinMainnet` (constants.py:210) and `set_as_network` assigns classes (:79–82). Works because every field is a class attribute, but the two conventions coexist; `lnaddr.py:266`'s `# type: Type[AbstractNet]` comment is only true pre-startup.
- **I6: `tests/test_tombstone.py:47` assigns a string** (`config.network = "signet"`) to a mock — passes only because nothing dereferences it. A landmine for whoever copies that fixture into a test that builds addresses/invoices.
- **I7: the mutinynet compose exists only on the inr2 box.** `docker/inr2-swapnet/README.md` (playground) states the mirror policy ("After changing the live stack, re-copy here and commit") and the mirror contains `docker-compose.yml` (signet) but not `docker-compose.mutinynet.yml`. Reproducibility gap if inr2 dies — the mutinynet stack's knowledge (fork image, `signetblocktime=30`, `ANN_NET_NAME`, port map) lives only on-box and in prose docs. Per task scope: documented, not fixed here.
- **I8 (cosmetic): dead code + dead comment** — `AbstractNet.set_as_network` (constants.py:79–82) has no callers; `tests_cln_lightning.py:18` is a commented-out network assignment. The constants file is an electrum port, so keeping upstream shape has parity value; flagging only.

---

## 4. Recommendations (conservative — money-path-adjacent config)

**Bottom line: the architecture is already right.** One net-global with a single write site, one `ANN_NET_NAME` resolver with one consumer, a `NETS_LIST` that auto-extends, and a network-agnostic image where all per-network truth lives in env. Nothing here warrants a structural refactor (no enum/dataclass registry — the class graph *is* the registry, and electrum-parity of `constants.py` is worth more than DRY wins inside it).

Ranked, minimal-diff-first:

- **R1 (recommended, 1-line-class diff, zero behavior change): collapse `BitcoinMutinynet` to `class BitcoinMutinynet(BitcoinSignet): NET_NAME = "mutinynet"`** (constants.py:198–204 → 2 lines). Identical field values (verified: only `NET_NAME` differs today), matches the file's own `BitcoinTestnet4` idiom. Guarded by the existing green tests (`test_ann_net_name_overrides_cln_network` pins the tag path; `NETS_LIST` membership is what validation reads).
- **R2 (documentation-only for now): the `__parse_network_type` registry collapse (D2).** Sketch the diff in this doc (below) but don't land it while three networks are live and frozen-stable — it changes error behavior for currently-rejected strings, and the mainnet name question (I1) should be settled in the same edit when mainnet is ever attempted. If landed, pin with a parametrized test over `NETS_LIST`.
- **R3 (documentation-only): I1 mainnet name mismatch.** File it as a precondition for any mainnet effort: accept `"bitcoin"` (and keep `"mainnet"` for humans) in `__parse_network_type`, aligning with `bitcoin_core_rpc.py:395/403`.
- **R4 (no action): keep `set_as_network` and the string-keyed conditionals as-is** (I8, D3). Electrum parity + working code; deletion is churn with no risk reduction.
- **R5 (operational, outside this repo's code): mirror `docker-compose.mutinynet.yml` into `lightning-playground docker/inr2-swapnet/` per that directory's own README policy (I7).** Documented here only, per audit scope.

**"What a new network requires today" — checklist (verified against the code):**

Path A — genesis-shared variant (mutinynet recipe):
1. Add the net class in `constants.py` (else startup fails `ANN_NET_NAME` validation — plugin_config.py:83–87). Inherit from the shared chain's class; override `NET_NAME` only.
2. Stand up a chain backend the CLN string can follow (fork bitcoind conf: `signetchallenge`, `signetblocktime`; prune ok — plugin is esplora-mode).
3. Point CLN at it with the *shared* network name in `lightning-config` (`network=signet` precedent) + rpc lines.
4. Deploy the **unmodified** `lab-cln-subswap` image with env: `ANN_NET_NAME=<new>`, `ESPLORA_URLS=<explorer>`, `ANN_POW_TARGET_BITS` ≤24 (in-process) or a pinned `ANN_POW_NONCE` for 30 (plugin_config.py:54–75), relays, fee knobs.
5. Register the net tag in consumers (electrum client constants; bridge-worker provider filter) — outside this repo.
6. Test: reuse `test_ann_net_name_overrides_cln_network` shape (tests/test_plugin_config_pow.py:99–115).

Path B — new CLN-visible network value:
1. `constants.py`: full class (NET_NAME, SEGWIT_HRP, BOLT11_HRP, GENESIS, …).
2. `plugin_config.py:13`: import.
3. `plugin_config.py:160–171`: parse branch (see I1 — use CLN's actual string).
4. `bitcoin_core_rpc.py:395`: rpcport default (only if ≠8332 and CLN may omit it).
5. Deployment env/conf (no `ANN_NET_NAME` needed — tag defaults to `NET_NAME`, plugin_config.py:76).
6. Optional: stub test with the new `network.value_str`.

---

## Evidence index

Code: constants.py:49–210 · plugin_config.py:13,26,46,54–75,76–88,160–171 · offer.py:74–81 · submarine_swaps.py:611,674,1111 · cln_lightning.py:504 · bitcoin.py:368–692 (21 sites) · bip32.py:107–137 · lnaddr.py:79–421 · descriptor.py:1058–1064 · bitcoin_core_rpc.py:27,127–132,391–414 · cln_chain.py:94–99 · utils.py:85–90.
Tests: test_plugin_config_pow.py:40–128 · test_e2e_bug_regressions.py:236–283 · test_tombstone.py:40–53 · test_protocol_contract.py:88 · tests_cln_lightning.py:18 · conftest.py (plugin_src shim).
Deployments: cln-plugin.Dockerfile:1–19 · playground docker/docker-compose.regtest.subswap.yml:13–47 · playground docker/subswap/build.sh · playground docker/inr2-swapnet/docker-compose.yml:59–83 (+README mirror policy) · inr2 box /opt/inr2-swapnet/deploy/docker-compose.mutinynet.yml:9–130, docker-compose.yml · on-box /opt/inr2-swapnet/{cln-swap-data,cln-swap-mutinynet-data,bitcoind-data,bitcoind-mutinynet-data} configs (secrets redacted).
History: `8c12e27` (BitcoinMutinynet + ANN_NET_NAME) · `git log --all -S SignetRegtest` → empty.
Verification: `pytest tests/test_plugin_config_pow.py tests/test_protocol_contract.py` → 11 passed, 1.20s, commit 94ac0cd, 2026-08-21.
