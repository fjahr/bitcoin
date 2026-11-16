# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Image that the silent merge check runs pull request code in. See
# .github/silent-merge-test.py.

FROM mirror.gcr.io/ubuntu:26.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      clang mold ccache build-essential cmake ninja-build pkgconf git python3 python3-pip \
      python3-zmq libevent-dev libboost-dev libsqlite3-dev systemtap-sdt-dev libzmq3-dev \
      qt6-base-dev qt6-tools-dev qt6-l10n-tools libqrencode-dev capnproto libcapnp-dev && \
    pip3 install --break-system-packages pycapnp && \
    rm -rf /var/lib/apt/lists/*
