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
#                   installed via pip below so the image is build-stable.
RUN apk add --no-cache \
        build-base cmake \
        libubox libubox-dev \
        iproute2 \
        python3 py3-pip \
        strace \
        libseccomp libseccomp-dev \
        bash tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

WORKDIR /src
COPY . /src

# Minimal build: no ubus (avoids ubusd); enable seccomp where the option exists
# (it is a no-op on trees without it). The harness points ODHCP6C_BIN at this.
RUN cmake -S . -B build -DUBUS=OFF $(grep -q 'option(SECCOMP' CMakeLists.txt && echo -DSECCOMP=ON) \
    && cmake --build build --parallel \
    && cp build/odhcp6c /usr/local/bin/odhcp6c

ENV ODHCP6C_BIN=/usr/local/bin/odhcp6c
ENV PYTHON=python3

# Default command lists the available scenarios; override with run-scenario.sh.
CMD ["sh", "-c", "tools/harness/run-scenario.sh --list"]
