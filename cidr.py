#!/usr/bin/env python3
"""cidr - IP/CIDR calculator and subnet toolkit.

Calculate subnets, check containment, split/merge ranges. Zero dependencies.
"""

import argparse
import socket
import struct
import sys


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n & 0xFFFFFFFF))


def parse_cidr(s):
    if "/" in s:
        ip, prefix = s.split("/")
        return ip_to_int(ip), int(prefix)
    return ip_to_int(s), 32


def network_addr(ip_int, prefix):
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask


def broadcast_addr(ip_int, prefix):
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_int & mask) | (~mask & 0xFFFFFFFF)


def cmd_info(args):
    ip_int, prefix = parse_cidr(args.cidr)
    net = network_addr(ip_int, prefix)
    bcast = broadcast_addr(ip_int, prefix)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    wildcard = ~mask & 0xFFFFFFFF
    total = 2 ** (32 - prefix)
    usable = max(total - 2, 1) if prefix < 31 else total

    # Classify
    first = (net >> 24) & 0xFF
    if first == 10 or (first == 172 and 16 <= ((net >> 16) & 0xFF) <= 31) or (first == 192 and ((net >> 16) & 0xFF) == 168):
        cls = "Private (RFC 1918)"
    elif first == 127:
        cls = "Loopback"
    elif first >= 224:
        cls = "Multicast" if first < 240 else "Reserved"
    else:
        cls = "Public"

    print(f"  Address:    {int_to_ip(ip_int)}/{prefix}")
    print(f"  Network:    {int_to_ip(net)}/{prefix}")
    print(f"  Broadcast:  {int_to_ip(bcast)}")
    print(f"  Netmask:    {int_to_ip(mask)}")
    print(f"  Wildcard:   {int_to_ip(wildcard)}")
    print(f"  First host: {int_to_ip(net + 1)}")
    print(f"  Last host:  {int_to_ip(bcast - 1)}")
    print(f"  Total IPs:  {total:,}")
    print(f"  Usable:     {usable:,}")
    print(f"  Class:      {cls}")


def cmd_contains(args):
    net_int, prefix = parse_cidr(args.cidr)
    net = network_addr(net_int, prefix)
    ip_int = ip_to_int(args.ip)
    ip_net = network_addr(ip_int, prefix)
    if ip_net == net:
        print(f"✓ {args.ip} is in {args.cidr}")
    else:
        print(f"✗ {args.ip} is NOT in {args.cidr}")
        sys.exit(1)


def cmd_split(args):
    ip_int, prefix = parse_cidr(args.cidr)
    net = network_addr(ip_int, prefix)
    new_prefix = prefix + args.bits
    if new_prefix > 32:
        print("Cannot split further")
        sys.exit(1)
    count = 2 ** args.bits
    subnet_size = 2 ** (32 - new_prefix)
    print(f"Splitting {args.cidr} into {count} /{new_prefix} subnets:")
    for i in range(count):
        snet = net + i * subnet_size
        print(f"  {int_to_ip(snet)}/{new_prefix}  ({subnet_size:,} IPs)")


def cmd_range(args):
    ip_int, prefix = parse_cidr(args.cidr)
    net = network_addr(ip_int, prefix)
    bcast = broadcast_addr(ip_int, prefix)
    if args.list:
        for i in range(net, bcast + 1):
            print(int_to_ip(i))
    else:
        print(f"  {int_to_ip(net)} - {int_to_ip(bcast)}")
        print(f"  {bcast - net + 1:,} addresses")


def cmd_overlap(args):
    a_int, a_prefix = parse_cidr(args.cidr1)
    b_int, b_prefix = parse_cidr(args.cidr2)
    a_net = network_addr(a_int, a_prefix)
    a_bcast = broadcast_addr(a_int, a_prefix)
    b_net = network_addr(b_int, b_prefix)
    b_bcast = broadcast_addr(b_int, b_prefix)

    if a_net <= b_bcast and b_net <= a_bcast:
        print(f"✓ {args.cidr1} and {args.cidr2} overlap")
        overlap_start = max(a_net, b_net)
        overlap_end = min(a_bcast, b_bcast)
        print(f"  Overlap: {int_to_ip(overlap_start)} - {int_to_ip(overlap_end)} ({overlap_end - overlap_start + 1:,} IPs)")
    else:
        print(f"✗ No overlap")


def cmd_supernet(args):
    """Find smallest CIDR covering all given CIDRs."""
    min_ip = 0xFFFFFFFF
    max_ip = 0
    for cidr in args.cidrs:
        ip_int, prefix = parse_cidr(cidr)
        net = network_addr(ip_int, prefix)
        bcast = broadcast_addr(ip_int, prefix)
        min_ip = min(min_ip, net)
        max_ip = max(max_ip, bcast)

    # Find smallest prefix that covers range
    for prefix in range(0, 33):
        net = network_addr(min_ip, prefix)
        bcast = broadcast_addr(min_ip, prefix)
        if net <= min_ip and bcast >= max_ip:
            print(f"  Supernet: {int_to_ip(net)}/{prefix}")
            print(f"  Covers: {int_to_ip(min_ip)} - {int_to_ip(max_ip)}")
            return
    print("Could not find supernet")


def main():
    p = argparse.ArgumentParser(description="IP/CIDR calculator")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("info", help="Subnet information").add_argument("cidr")

    cp = sub.add_parser("contains", help="Check if IP is in CIDR")
    cp.add_argument("cidr")
    cp.add_argument("ip")

    sp = sub.add_parser("split", help="Split into smaller subnets")
    sp.add_argument("cidr")
    sp.add_argument("bits", type=int, help="Additional prefix bits")

    rp = sub.add_parser("range", help="Show IP range")
    rp.add_argument("cidr")
    rp.add_argument("--list", action="store_true", help="List all IPs")

    op = sub.add_parser("overlap", help="Check CIDR overlap")
    op.add_argument("cidr1")
    op.add_argument("cidr2")

    snp = sub.add_parser("supernet", help="Find covering supernet")
    snp.add_argument("cidrs", nargs="+")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    {"info": cmd_info, "contains": cmd_contains, "split": cmd_split,
     "range": cmd_range, "overlap": cmd_overlap, "supernet": cmd_supernet}[args.cmd](args)


if __name__ == "__main__":
    main()
