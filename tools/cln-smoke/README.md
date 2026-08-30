# cln-smoke — docker packaging + demo for branch-built CLN trees

Companion to `docs/upstream-9452-change-for-emergency.md`: the docker leg
of a core-fix campaign (the pyln harness in a CLN checkout is the
authoritative verification; this kit packages a built tree for
production-shaped smoke on the regtest lab).

## Pieces

| File | What |
|---|---|
| `Dockerfile` | wraps a `make install DESTDIR=…` tree + the plugin layers (glibc-matched ubuntu:24.04; runtime libs: libsodium, libsecp256k1-1 — both earned) |
| `overlay.yml` | lab overlay pattern: custom images need an explicit `lightningd` entrypoint; tip builds against a v26.06 lab volume need `--database-upgrade=true` |
| `smoke.sh` | the 9452 crash-window demo: fixed → `TYPED-ERROR`, unfixed → `CRASH-REPRODUCED`. Funding discovery via `listfunds` (gettransaction-details parsing is a shape trap) |

## Flow

```bash
# 1. build the tree (playground scripts/cln-build.sh has the recipe)
make -C <cln-tree> install DESTDIR=<cln-tree>/install
# 2. stage the build context
mkdir -p ctx && cp -r <cln-tree>/install/usr/local ctx/cln-install/usr.local/…
#    (keep the Dockerfile's expected layout: cln-install/usr/local)
cp ../plugin_src/requirements.txt ctx/plugin-requirements.txt
cp -r ../swap-provider ctx/swap-provider
cp Dockerfile ctx/
docker build -t cln-<ref>-smoke --build-arg SWAP_PROVIDER_VERSION=<ref> ctx
# 3. demo (against the running regtest lab)
docker run --rm -v "$PWD/smoke.sh:/smoke.sh" --network regtest-lab_default \
  cln-<ref>-smoke bash /smoke.sh
```

## Earned notes (2026-08-30 campaign)

- The smoke's earlier `gettransaction`-details parsing was flaky and was
  replaced by `listfunds` discovery before this kit was promoted; the
  in-container demo leg was NOT re-run after that rewrite — the pyln
  regressions carry the authoritative RED/GREEN evidence, and this
  script's verdict logic is identical in shape to the tested pyln
  assertions. Re-run it as part of the next core-fix campaign.
- Tip-vs-electrum-4.8.1 peering: upstream-tip lightningd RESETS the INIT
  exchange with the lab's electrum peers — swap-leg testing on tip builds
  needs a CLN-only topology (which is what the pyln harness is).
- Post-campaign: restore the lab with `docker/lab-reset.sh --subswap`.
