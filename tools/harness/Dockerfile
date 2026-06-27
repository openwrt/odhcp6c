# tools/harness/Dockerfile
#
# Hermetic image for the odhcp6c DHCPv6/RA integration harness.
#
# Default base: Alpine (musl) -- a fast proxy for the OpenWrt musl target.
# The image builds odhcp6c from the repository and installs everything the
# harness needs: iproute2 (netns + veth), python3 + scapy (crafted-packet
# backend), odhcpd (real-server backend), strace and seccomp tooling (trace
# modes).
#
# Build (from the repository root):
#   docker build -f tools/harness/Dockerfile -t odhcp6c-harness .
#
# Run a scenario (needs NET_ADMIN + SYS_ADMIN for netns/veth; `ip netns add`
# does a `mount --make-shared /run/netns` that the default cap set and AppArmor
# profile both block):
#   docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#       --security-opt apparmor=unconfined odhcp6c-harness \
#       tools/harness/run-scenario.sh stateful-basic
#
# Trace mode additionally needs SYS_PTRACE and an unconfined seccomp profile:
#   docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE \
#       --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
#       odhcp6c-harness \
#       tools/harness/run-scenario.sh --trace=strace renew-rebind
#
# Variants: see the "Debian / glibc variant" and "OpenWrt rootfs" notes in
# tools/harness/README.md. The glibc variant only differs in the base image and
# package manager; the harness scripts are identical.

FROM alpine:3.24.1

# Build + runtime dependencies.
#   build-base cmake          - compile odhcp6c
#   libubox / libubox-dev     - md5 + list helpers odhcp6c links against
#   iproute2                  - ip netns / veth
#   python3 + scapy           - crafted-packet backend (RA + DHCPv6)
#   strace                    - --trace=strace
#   libseccomp / libseccomp-dev - the N-2 seccomp build
#   bash                      - the harness scripts target POSIX sh but bash is
#                               handy for interactive debugging
#
# Notes on omitted packages:
#   odhcpd        - an OpenWrt package, not in the Alpine repositories. It is
#                   only the optional real-server backend; scapy is the default
#                   backend used by every harness scenario, so it is omitted.
#   seccomp-tools - not in the Alpine repositories. It is only used by the
#                   optional --trace=seccomp-log mode, which degrades gracefully
#                   when the tool is absent.
#   py3-scapy     - not reliably packaged across Alpine releases; scapy is
#                   installed via pip from the pinned requirements file below so
#                   the image is build-stable.
RUN apk add --no-cache \
        build-base cmake \
        libubox libubox-dev \
        iproute2 \
        python3 py3-pip \
        strace \
        libseccomp libseccomp-dev \
        libcap-ng libcap-ng-dev \
        bash tcpdump

# Install the Python backend dependencies from the pinned requirements file
# (copied on its own first so this layer caches independently of the sources).
COPY tools/harness/servers/requirements.txt /tmp/harness-requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/harness-requirements.txt

WORKDIR /src
COPY . /src

# ubus stack (built by default; override with --build-arg UBUS=OFF). ubus is the
# main OpenWrt configuration, so every harness image builds it in and the
# ubus-reconnect scenario runs as part of the standard matrix rather than a
# separate job. Build libubox + ubus from the upstream mirrors (the same repos CI
# uses in .github/workflows/ci.yml) into /usr so the musl loader finds the shared
# libs on its default path, and install ubusd + the ubus CLI for the harness to
# drive. json-c is ubus' JSON dependency. With UBUS=OFF the image builds the
# non-ubus odhcp6c instead and the ubus-reconnect scenario self-skips.
ARG UBUS=ON
RUN if [ "$UBUS" = "ON" ]; then set -eux; \
        apk add --no-cache git json-c-dev pkgconf; \
        git clone --depth=1 https://github.com/openwrt/libubox.git /tmp/libubox; \
        cmake -S /tmp/libubox -B /tmp/libubox/build \
            -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF -DBUILD_STATIC=OFF \
            -DCMAKE_INSTALL_PREFIX=/usr; \
        cmake --build /tmp/libubox/build --parallel; \
        cmake --install /tmp/libubox/build; \
        git clone --depth=1 https://github.com/openwrt/ubus.git /tmp/ubus; \
        cmake -S /tmp/ubus -B /tmp/ubus/build \
            -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF \
            -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr; \
        cmake --build /tmp/ubus/build --parallel; \
        cmake --install /tmp/ubus/build; \
        rm -rf /tmp/libubox /tmp/ubus; \
    fi

# Build odhcp6c: ubus is on by default (UBUS build-arg above); enable the
# exploit-mitigation (hardening) flags and libcap-ng so privilege separation is
# actually compiled in -- privsep_should_enable() is gated on WITH_LIBCAP_NG, so
# without it odhcp6c silently runs single-process. Seccomp confinement of the
# worker is opt-in via the SECCOMP build-arg (default OFF): the integration
# matrix builds a SECCOMP=ON image for the libcapng-seccomp cell and leaves it
# OFF for the others. The grep guards keep each flag a no-op on trees without
# the option. The harness points ODHCP6C_BIN at this.
ARG SECCOMP=OFF
RUN cmake -S . -B build -DHARDENING=ON -DCMAKE_PREFIX_PATH=/usr \
        $([ "$UBUS" = "ON" ] && echo -DUBUS=ON || echo -DUBUS=OFF) \
        $(grep -q 'option(LIBCAP_NG' CMakeLists.txt && echo -DLIBCAP_NG=ON) \
        $([ "$SECCOMP" = "ON" ] && grep -q 'option(SECCOMP' CMakeLists.txt && echo -DSECCOMP=ON) \
    && cmake --build build --parallel \
    && cp build/odhcp6c /usr/local/bin/odhcp6c

# [privsep-debug] Prove whether privilege separation was actually compiled
# into the binary-under-test, so a single-process CI result can be pinned to
# the build (this layer) vs. the runtime. Remove once the privsep axis is green.
RUN echo "[privsep-debug] LIBCAP_NG flag => [$(grep -q 'option(LIBCAP_NG' CMakeLists.txt && echo -DLIBCAP_NG=ON)]"; \
    grep -i 'LIBCAP_NG' build/CMakeCache.txt || echo "[privsep-debug] (LIBCAP_NG not in CMakeCache)"; \
    if readelf -d /usr/local/bin/odhcp6c 2>/dev/null | grep -qi 'cap-ng'; then \
        echo "[privsep-debug] linked libcap-ng = YES"; \
    else echo "[privsep-debug] linked libcap-ng = NO"; fi; \
    if strings /usr/local/bin/odhcp6c 2>/dev/null | grep -q 'staying single-process'; then \
        echo "[privsep-debug] WITH_LIBCAP_NG compiled = YES"; \
    else echo "[privsep-debug] WITH_LIBCAP_NG compiled = NO"; fi; \
    if readelf -d /usr/local/bin/odhcp6c 2>/dev/null | grep -qi 'libseccomp'; then \
        echo "[privsep-debug] linked libseccomp (SECCOMP build) = YES"; \
    else echo "[privsep-debug] linked libseccomp (SECCOMP build) = NO"; fi

ENV ODHCP6C_BIN=/usr/local/bin/odhcp6c
ENV PYTHON=python3

# Default command lists the available scenarios; override with run-scenario.sh.
CMD ["sh", "-c", "tools/harness/run-scenario.sh --list"]
