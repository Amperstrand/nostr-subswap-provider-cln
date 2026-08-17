# CLN image with the subswap provider plugin ready to run.
# Built from the lightning-playground lab overlay
# (docker-compose.regtest.subswap.yml); the plugin is launched by CLN
# via --plugin=/opt/swap-provider/swap-provider.py (python's sys.path[0]
# = script dir, so `from plugin.…` resolves).
FROM elementsproject/lightningd:v26.06

RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY swap-provider/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
      -r /tmp/requirements.txt

COPY swap-provider /opt/swap-provider
