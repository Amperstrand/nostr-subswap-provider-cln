# Package a host-built CLN tree (make install DESTDIR=...) + the swap
# provider plugin layers into a runnable image. Binary compatibility:
# build and runtime must match glibc (ubuntu:24.04 both sides).
# Usage: put cln-install/usr/local (the DESTDIR install tree) beside this
# Dockerfile, plus plugin-requirements.txt and swap-provider/, then:
#   docker build -t cln-<ref>-smoke --build-arg SWAP_PROVIDER_VERSION=<ref> .
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsqlite3-0 libgmp10 zlib1g python3 python3-pip libssl3 \
      ca-certificates libsodium23 libsecp256k1-1 \
    && rm -rf /var/lib/apt/lists/*
ENV ELECTRUM_ECC_DONT_COMPILE=1
ARG SWAP_PROVIDER_VERSION=dev
ENV SWAP_PROVIDER_VERSION=cln-subswap/${SWAP_PROVIDER_VERSION}
COPY cln-install/usr/local /usr/local
COPY plugin-requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt
COPY swap-provider /opt/swap-provider
