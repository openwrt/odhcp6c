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
# Run a scenario (needs NET_ADMIN for netns/veth):
#   docker run --rm --cap-add=NET_ADMIN odhcp6c-harness \
#       tools/harness/run-scenario.sh stateful-basic
#
# Trace mode additionally needs SYS_PTRACE and an unconfined seccomp profile:
#   docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_PTRACE \
#       --security-opt seccomp=unconfined odhcp6c-harness \
#       tools/harness/run-scenario.sh --trace=strace renew-rebind
#
# Variants: see the "Debian / glibc variant" and "OpenWrt rootfs" notes in
# tools/harness/README.md. The glibc variant only differs in the base image and
# package manager; the harness scripts are identical.

FROM alpine:3.20

# Build + runtime dependencies.
#   build-base cmake          - compile odhcp6c
#   libubox / libubox-dev     - md5 + list helpers odhcp6c links against
#   iproute2                  - ip netns / veth
#   python3 + py3-scapy       - crafted-packet backend (RA + DHCPv6)
#   odhcpd                    - optional real-server backend
#   strace                    - --trace=strace
#   libseccomp / seccomp-tools- --trace=seccomp-log and the N-2 seccomp build
#   bash                      - the harness scripts target POSIX sh but bash is
#                               handy for interactive debugging
RUN apk add --no-cache \
        build-base cmake \
        libubox libubox-dev \
        iproute2 \
        python3 py3-scapy \
        odhcpd \
        strace \
        libseccomp libseccomp-dev seccomp-tools \
        bash tcpdump \
    || ( \
        # py3-scapy / seccomp-tools live in the community repo on some mirrors;
        # retry with it enabled and fall back to pip for scapy.
        echo "https://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories && \
        apk add --no-cache \
            build-base cmake libubox libubox-dev iproute2 python3 py3-pip \
            odhcpd strace libseccomp libseccomp-dev bash tcpdump && \
        pip3 install --break-system-packages scapy \
    )

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
