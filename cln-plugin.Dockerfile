# CLN image with the subswap provider plugin ready to run.
# Built from the lightning-playground lab overlay
# (docker-compose.regtest.subswap.yml); the plugin is launched by CLN
# via --plugin=/opt/swap-provider/swap-provider.py (python's sys.path[0]
# = script dir, so `from plugin.…` resolves).
FROM elementsproject/lightningd:v26.06

RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-pip libsecp256k1-dev \
    && rm -rf /var/lib/apt/lists/*

# electrum_ecc would compile its bundled libsecp256k1 (needs autotools);
# use the system lib instead (proven in the lab's electrum images)
ENV ELECTRUM_ECC_DONT_COMPILE=1

# self-ID published in the nostr offer (content.server_version); baked
# from `git describe` at build time so the announcement identifies the
# exact source the provider runs (bridge-side fingerprinting reads it)
ARG SWAP_PROVIDER_VERSION=dev
ENV SWAP_PROVIDER_VERSION=cln-subswap/${SWAP_PROVIDER_VERSION}

COPY swap-provider/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
      -r /tmp/requirements.txt

COPY swap-provider /opt/swap-provider
