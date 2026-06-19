#!/usr/bin/env python3
"""
scapy_server.py - crafted-packet DHCPv6 server + RA sender for the odhcp6c
integration harness.

This is the "crafted-packet backend": it emits exactly the RA / DHCPv6 packets a
scenario needs, which lets the harness deterministically hit edge branches that a
real server (odhcpd) will not reliably emit. It can also act as a normal-ish
server for the happy-path stateful flows.

It uses scapy's layer-2 send (sendp) on a veth, so it works purely at the link
layer and does not depend on the host IPv6 stack accepting/forwarding anything.

Subcommands:

  ra       Periodically multicast Router Advertisements (optionally responding to
           Router Solicitations). All RA option contents -- and several
           deliberate malformations -- are controlled by flags.

  dhcpv6   Act as a DHCPv6 server: answer SOLICIT with ADVERTISE and
           REQUEST/RENEW/REBIND with REPLY, populating IA_NA, IA_PD and the
           common informational options. INFORMATION-REQUEST is answered with a
           stateless REPLY. Honors RELEASE (logs it).

  serve    Run both `ra` and `dhcpv6` together (the production-like happy path).

Run `scapy_server.py <subcommand> --help` for the full flag list.
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

# Keep scapy quiet and fast.
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
from scapy.all import sendp, sniff, get_if_hwaddr, Ether, Raw  # noqa: E402
from scapy.layers.inet6 import (  # noqa: E402
    IPv6,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptMTU,
    ICMPv6NDOptRDNSS,
    ICMPv6NDOptRouteInfo,
    ICMPv6NDOptDNSSL,
)
from scapy.layers.dhcp6 import (  # noqa: E402
    DHCP6_Solicit,
    DHCP6_Request,
    DHCP6_Renew,
    DHCP6_Rebind,
    DHCP6_Release,
    DHCP6_InfoRequest,
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6OptClientId,
    DHCP6OptServerId,
    DHCP6OptIA_NA,
    DHCP6OptIA_PD,
    DHCP6OptIAAddress,
    DHCP6OptIAPrefix,
    DHCP6OptDNSServers,
    DHCP6OptDNSDomains,
    DHCP6OptNTPServer,
    DUID_LL,
)

ALL_NODES_MAC = "33:33:00:00:00:01"
ALL_DHCP_RELAY = "ff02::1:2"


def log(*a):
    print("[scapy]", *a, flush=True)


def link_local(iface):
    out = subprocess.check_output(
        ["ip", "-6", "addr", "show", "dev", iface, "scope", "link"]
    ).decode()
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("inet6"):
            return ln.split()[1].split("/")[0]
    raise RuntimeError("no link-local address on %s" % iface)


# ---------------------------------------------------------------------------
# RA construction
# ---------------------------------------------------------------------------

def build_captive_portal_opt(uri_bytes):
    """Hand-build an ND_OPT_CAPTIVE_PORTAL (type 37, RFC8910).

    Layout: type(1) len(1, in 8-byte units) uri... padded to an 8-byte boundary.
    odhcp6c computes uri_len = len*8 - 2, so callers can intentionally leave the
    URI unpadded / non-NUL-terminated to exercise the boundary handling.
    """
    total = 2 + len(uri_bytes)
    units = (total + 7) // 8
    pad = units * 8 - total
    return bytes([37, units]) + uri_bytes + (b"\x00" * pad)


def build_ra(args, server_mac, server_ll):
    hlim = args.hoplimit
    src = args.source or server_ll
    ra = (
        Ether(src=server_mac, dst=ALL_NODES_MAC)
        / IPv6(src=src, dst="ff02::1", hlim=hlim)
        / ICMPv6ND_RA(
            routerlifetime=args.router_lifetime,
            M=1 if args.managed else 0,
            O=1 if args.other else 0,
            reachabletime=args.reachable,
            retranstimer=args.retransmit,
            chlim=args.cur_hoplimit,
        )
        / ICMPv6NDOptSrcLLAddr(lladdr=server_mac)
    )

    if args.mtu is not None:
        ra /= ICMPv6NDOptMTU(mtu=args.mtu)

    if args.prefix:
        ra /= ICMPv6NDOptPrefixInfo(
            prefixlen=args.prefix_len,
            prefix=args.prefix,
            validlifetime=args.prefix_valid,
            preferredlifetime=args.prefix_preferred,
            A=1,
            L=1,
        )

    if args.rdnss:
        ra /= ICMPv6NDOptRDNSS(lifetime=args.rdnss_lifetime, dns=args.rdnss)

    if args.dnssl:
        ra /= ICMPv6NDOptDNSSL(lifetime=args.rdnss_lifetime, searchlist=args.dnssl)

    if args.route_info:
        ra /= ICMPv6NDOptRouteInfo(
            plen=args.route_info_plen,
            prefix=args.route_info,
            rtlifetime=args.route_info_lifetime,
        )

    # ----- deliberate malformations (edge-case scenarios) -----
    if args.raw_route_info_len0:
        # ND_OPT_ROUTE_INFORMATION (type 24) with the length field set to 0.
        ra /= Raw(bytes([24, 0, 0, 0]))
    if args.raw_rdnss_odd:
        # ND_OPT_RECURSIVE_DNS (type 25) with an odd/short length that does not
        # match the contained address bytes (H-2 parser hardening).
        ra /= Raw(bytes([25, 1, 0, 0, 0, 0, 0, 0]))
    if args.captive_portal is not None:
        ra /= Raw(build_captive_portal_opt(args.captive_portal.encode("latin-1",
                                                                       "backslashreplace")))
    if args.captive_portal_unrestricted:
        ra /= Raw(build_captive_portal_opt(b"urn:ietf:params:capport:unrestricted"))
    if args.raw_trailer:
        ra /= Raw(bytes.fromhex(args.raw_trailer))

    return ra


def ra_loop(args, iface, server_mac, server_ll, stop):
    ra = build_ra(args, server_mac, server_ll)
    sent = 0
    while not stop.is_set() and (args.count == 0 or sent < args.count):
        sendp(ra, iface=iface, verbose=0)
        sent += 1
        log("sent RA #%d" % sent)
        stop.wait(args.interval)


def rs_responder(args, iface, server_mac, server_ll, stop):
    def handle(pkt):
        if stop.is_set():
            return
        if pkt.haslayer(ICMPv6ND_RS):
            ra = build_ra(args, server_mac, server_ll)
            ra[Ether].dst = pkt[Ether].src
            sendp(ra, iface=iface, verbose=0)
            log("sent RA in response to RS from", pkt[Ether].src)

    sniff(iface=iface, prn=handle, store=0,
          filter="icmp6", stop_filter=lambda p: stop.is_set())


# ---------------------------------------------------------------------------
# DHCPv6 server
# ---------------------------------------------------------------------------

def client_ia_iaids(pkt):
    """Extract the IA_NA / IA_PD IAIDs the client chose, so the server can echo
    them back.

    A DHCPv6 client picks an arbitrary IAID per IA and the server MUST return
    the matching IAID; odhcp6c derives its IA_NA IAID from a hash of the
    interface name and *discards* any IA_NA whose IAID does not match (see
    dhcpv6.c, "Test ID"). Hard-coding the IAID would therefore make the address
    silently disappear from the lease. Defaults mirror the historical value so a
    request without the option still elicits a reply.
    """
    na_iaid = pkt[DHCP6OptIA_NA].iaid if pkt.haslayer(DHCP6OptIA_NA) else 1
    pd_iaid = pkt[DHCP6OptIA_PD].iaid if pkt.haslayer(DHCP6OptIA_PD) else 1
    return na_iaid, pd_iaid


def build_ia_options(args, na_iaid=1, pd_iaid=1):
    opts = []
    if not args.no_na:
        opts.append(
            DHCP6OptIA_NA(
                iaid=na_iaid, T1=args.t1, T2=args.t2,
                ianaopts=[DHCP6OptIAAddress(
                    addr=args.address,
                    preflft=args.preferred, validlft=args.valid)],
            )
        )
    if not args.no_pd:
        opts.append(
            DHCP6OptIA_PD(
                iaid=pd_iaid, T1=args.t1, T2=args.t2,
                iapdopt=[DHCP6OptIAPrefix(
                    prefix=args.pd_prefix, plen=args.pd_len,
                    preflft=args.preferred, validlft=args.valid)],
            )
        )
    return opts


def build_info_options(args):
    opts = []
    if args.dns:
        opts.append(DHCP6OptDNSServers(dnsservers=args.dns))
    if args.domains:
        opts.append(DHCP6OptDNSDomains(dnsdomains=args.domains))
    if args.ntp:
        # NTP server option (RFC 5908) suboption 1 (server address).
        opts.append(DHCP6OptNTPServer(ntpserver=[]))
    return opts


def build_s46_mape_bytes():
    """Raw bytes for OPTION_S46_CONT_MAPE (94) carrying one MAP-E rule + BR.

    Layout follows RFC 7598 and odhcp6c's struct dhcpv6_s46_rule:
      rule = flags(1) ea_len(1) prefix4_len(1) ipv4_prefix(4)
             prefix6_len(1) ipv6_prefix(ceil(prefix6_len/8))
    Scapy has no class for option 94, so we emit the TLVs by hand and append
    them to the reply as a raw payload (DHCPv6 options are concatenated TLVs).
    """
    import socket
    import struct

    flags = 0x01           # FMR
    ea_len = 16
    prefix4_len = 24
    ipv4_prefix = socket.inet_pton(socket.AF_INET, "192.0.2.0")
    prefix6_len = 64
    ipv6_full = socket.inet_pton(socket.AF_INET6, "2001:db8:ce::")
    ipv6_prefix = ipv6_full[:(prefix6_len + 7) // 8]
    rule = struct.pack("!BBB", flags, ea_len, prefix4_len) + ipv4_prefix \
        + struct.pack("!B", prefix6_len) + ipv6_prefix
    opt_rule = struct.pack("!HH", 89, len(rule)) + rule

    br = socket.inet_pton(socket.AF_INET6, "2001:db8:ffff::1")
    opt_br = struct.pack("!HH", 90, len(br)) + br

    container = opt_rule + opt_br
    return struct.pack("!HH", 94, len(container)) + container


def dhcpv6_server(args, iface, server_mac, server_ll, stop):
    srvid = DUID_LL(lladdr=server_mac)

    def handle(pkt):
        if not pkt.haslayer(IPv6):
            return
        # During the shutdown drain window `stop` is already set: keep recording
        # an inbound RELEASE (the reason the drain exists) but stop generating
        # new replies so we don't answer requests while tearing down.
        shutting_down = stop.is_set()
        from scapy.layers.inet import UDP
        eth_dst = pkt[Ether].src
        ip_dst = pkt[IPv6].src

        def base(msgcls, trid, clientid):
            return (
                Ether(src=server_mac, dst=eth_dst)
                / IPv6(src=server_ll, dst=ip_dst)
                / UDP(sport=547, dport=546)
                / msgcls(trid=trid)
                / DHCP6OptClientId(duid=clientid)
                / DHCP6OptServerId(duid=srvid)
            )

        if not shutting_down and pkt.haslayer(DHCP6_Solicit):
            cid = pkt[DHCP6OptClientId].duid
            na_iaid, pd_iaid = client_ia_iaids(pkt)
            rep = base(DHCP6_Advertise, pkt[DHCP6_Solicit].trid, cid)
            for o in build_ia_options(args, na_iaid, pd_iaid) + build_info_options(args):
                rep /= o
            if getattr(args, "mape", False):
                rep /= Raw(load=build_s46_mape_bytes())
            if getattr(args, "reply_raw_trailer", None):
                try:
                    _trailer = bytes.fromhex(args.reply_raw_trailer)
                except ValueError as e:
                    log(f"invalid --reply-raw-trailer hex: {e}")
                    stop.set()
                    return
                rep /= Raw(load=_trailer)
            sendp(rep, iface=iface, verbose=0)
            log("ADVERTISE -> solicit")
        elif not shutting_down and (pkt.haslayer(DHCP6_Request)
                or pkt.haslayer(DHCP6_Renew) or pkt.haslayer(DHCP6_Rebind)):
            for cls in (DHCP6_Request, DHCP6_Renew, DHCP6_Rebind):
                if pkt.haslayer(cls):
                    trid = pkt[cls].trid
                    break
            cid = pkt[DHCP6OptClientId].duid
            na_iaid, pd_iaid = client_ia_iaids(pkt)
            rep = base(DHCP6_Reply, trid, cid)
            for o in build_ia_options(args, na_iaid, pd_iaid) + build_info_options(args):
                rep /= o
            if getattr(args, "mape", False):
                rep /= Raw(load=build_s46_mape_bytes())
            if getattr(args, "reply_raw_trailer", None):
                try:
                    _trailer = bytes.fromhex(args.reply_raw_trailer)
                except ValueError as e:
                    log(f"invalid --reply-raw-trailer hex: {e}")
                    stop.set()
                    return
                rep /= Raw(load=_trailer)
            sendp(rep, iface=iface, verbose=0)
            log("REPLY -> request/renew/rebind")
        elif not shutting_down and pkt.haslayer(DHCP6_InfoRequest):
            cid = pkt[DHCP6OptClientId].duid if pkt.haslayer(DHCP6OptClientId) \
                else b"\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00"
            rep = base(DHCP6_Reply, pkt[DHCP6_InfoRequest].trid, cid)
            for o in build_info_options(args):
                rep /= o
            sendp(rep, iface=iface, verbose=0)
            log("REPLY -> information-request (stateless)")
        elif pkt.haslayer(DHCP6_Release):
            log("RELEASE received")

    sniff(iface=iface, prn=handle, store=0,
          filter="udp port 547",
          stop_filter=lambda p: stop.is_set())


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def add_ra_args(p):
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--count", type=int, default=0, help="0 = forever")
    p.add_argument("--respond-rs", action="store_true",
                   help="also answer Router Solicitations")
    p.add_argument("--router-lifetime", type=int, default=1800)
    p.add_argument("--managed", action="store_true")
    p.add_argument("--other", action="store_true")
    p.add_argument("--reachable", type=int, default=30000)
    p.add_argument("--retransmit", type=int, default=1000)
    p.add_argument("--cur-hoplimit", type=int, default=64)
    p.add_argument("--hoplimit", type=int, default=255,
                   help="IPv6 hop limit (must be 255 to be accepted)")
    p.add_argument("--source", default=None,
                   help="override IPv6 source (use a non-link-local to test drop)")
    p.add_argument("--mtu", type=int, default=None)
    p.add_argument("--prefix", default=None)
    p.add_argument("--prefix-len", type=int, default=64)
    p.add_argument("--prefix-valid", type=int, default=7200)
    p.add_argument("--prefix-preferred", type=int, default=3600)
    p.add_argument("--rdnss", action="append", default=[])
    p.add_argument("--rdnss-lifetime", type=int, default=1800)
    p.add_argument("--dnssl", action="append", default=[])
    p.add_argument("--route-info", default=None)
    p.add_argument("--route-info-plen", type=int, default=48)
    p.add_argument("--route-info-lifetime", type=int, default=1800)
    p.add_argument("--captive-portal", default=None,
                   help="captive-portal URI to advertise (may contain metachars)")
    p.add_argument("--captive-portal-unrestricted", action="store_true")
    # malformations
    p.add_argument("--raw-route-info-len0", action="store_true")
    p.add_argument("--raw-rdnss-odd", action="store_true")
    p.add_argument("--raw-trailer", default=None,
                   help="hex bytes appended verbatim after all options")


def add_dhcpv6_args(p):
    p.add_argument("--t1", type=int, default=300)
    p.add_argument("--t2", type=int, default=500)
    p.add_argument("--preferred", type=int, default=3600)
    p.add_argument("--valid", type=int, default=7200)
    p.add_argument("--address", default="2001:db8:1::1000")
    p.add_argument("--pd-prefix", default="2001:db8:abcd::")
    p.add_argument("--pd-len", type=int, default=56)
    p.add_argument("--no-na", action="store_true")
    p.add_argument("--no-pd", action="store_true")
    p.add_argument("--dns", action="append", default=["2001:db8:1::53"])
    p.add_argument("--domains", action="append", default=["example.test"])
    p.add_argument("--ntp", action="store_true")
    p.add_argument("--mape", action="store_true",
                   help="include an S46 MAP-E container (OPTION_S46_CONT_MAPE)")
    p.add_argument("--reply-raw-trailer", default=None,
                   help="hex bytes appended verbatim after all options in the "
                        "ADVERTISE and REPLY (DHCPv6 negative-path parser tests)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ra = sub.add_parser("ra")
    add_ra_args(p_ra)

    p_dh = sub.add_parser("dhcpv6")
    add_dhcpv6_args(p_dh)

    p_se = sub.add_parser("serve")
    add_ra_args(p_se)
    add_dhcpv6_args(p_se)

    args = ap.parse_args()
    iface = args.iface
    server_mac = get_if_hwaddr(iface)
    server_ll = link_local(iface)
    log("iface=%s mac=%s ll=%s cmd=%s" % (iface, server_mac, server_ll, args.cmd))

    stop = threading.Event()

    def _sig(_s, _f):
        stop.set()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    threads = []
    persistent = False  # true if any thread runs until signalled (a sniffer)
    if args.cmd in ("ra", "serve"):
        threads.append(threading.Thread(
            target=ra_loop, args=(args, iface, server_mac, server_ll, stop),
            daemon=True))
        if args.respond_rs:
            persistent = True
            threads.append(threading.Thread(
                target=rs_responder,
                args=(args, iface, server_mac, server_ll, stop), daemon=True))
    if args.cmd in ("dhcpv6", "serve"):
        persistent = True
        threads.append(threading.Thread(
            target=dhcpv6_server,
            args=(args, iface, server_mac, server_ll, stop), daemon=True))

    for t in threads:
        t.start()
    log("ready")
    try:
        if persistent or args.count == 0:
            # Long-running: serve until signalled.
            while not stop.is_set():
                time.sleep(0.2)
        else:
            # One-shot: a finite RA burst with no listener. Exit when the burst
            # completes so callers (harness_inject) do not block forever.
            for t in threads:
                t.join()
            stop.set()
    except KeyboardInterrupt:
        stop.set()

    # Bounded shutdown drain: SIGTERM/SIGINT is delivered to the main thread and
    # interrupts the sleep above, so without this the process would tear down its
    # daemon sniffer threads almost immediately. A frame that the kernel placed
    # in the capture buffer just before shutdown -- e.g. the DHCPv6 RELEASE that
    # odhcp6c emits as it exits, right before the harness stops us -- would then
    # be lost. Yield briefly so the still-running sniffer threads can lift any
    # such buffered packet out of the ring (and run their prn) before we exit.
    if persistent:
        _drain_deadline = time.monotonic() + 0.5
        while time.monotonic() < _drain_deadline:
            time.sleep(0.05)

    log("stopping")


if __name__ == "__main__":
    main()
