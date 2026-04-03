#!/usr/bin/env python3
"""cidr - CIDR/subnet calculator and IP range tool.

Analyze CIDR blocks, check IP membership, calculate subnets, and convert
between CIDR notation and IP ranges.

Usage:
    cidr info 192.168.1.0/24
    cidr contains 10.0.0.0/8 10.0.1.50
    cidr range 192.168.1.100 192.168.1.200
    cidr split 10.0.0.0/16 --into 24
    cidr overlap 192.168.0.0/16 192.168.1.0/24
    cidr summarize 192.168.1.0/25 192.168.1.128/25
"""
import argparse
import ipaddress
import sys


def cmd_info(args):
    """Show detailed info about a CIDR block."""
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  Network:     {net.network_address}/{net.prefixlen}")
    print(f"  Netmask:     {net.netmask}")
    if hasattr(net, 'hostmask'):
        print(f"  Wildcard:    {net.hostmask}")
    print(f"  Broadcast:   {net.broadcast_address}")
    print(f"  First host:  {net.network_address + 1}" if net.num_addresses > 2 else f"  First host:  {net.network_address}")
    print(f"  Last host:   {net.broadcast_address - 1}" if net.num_addresses > 2 else f"  Last host:   {net.broadcast_address}")
    print(f"  Addresses:   {net.num_addresses:,}")
    usable = max(0, net.num_addresses - 2) if net.version == 4 and net.prefixlen < 31 else net.num_addresses
    print(f"  Usable:      {usable:,}")
    print(f"  Version:     IPv{net.version}")
    print(f"  Private:     {net.is_private}")
    print(f"  Class:       {_ip_class(net)}") if net.version == 4 else None

    # Binary representation for IPv4
    if net.version == 4:
        addr_int = int(net.network_address)
        mask_int = int(net.netmask)
        addr_bin = f"{addr_int:032b}"
        mask_bin = f"{mask_int:032b}"
        addr_dotted = ".".join(addr_bin[i:i+8] for i in range(0, 32, 8))
        mask_dotted = ".".join(mask_bin[i:i+8] for i in range(0, 32, 8))
        print(f"  Binary addr: {addr_dotted}")
        print(f"  Binary mask: {mask_dotted}")


def _ip_class(net):
    first_octet = int(net.network_address) >> 24
    if first_octet < 128: return "A"
    if first_octet < 192: return "B"
    if first_octet < 224: return "C"
    if first_octet < 240: return "D (multicast)"
    return "E (reserved)"


def cmd_contains(args):
    """Check if an IP is within a CIDR block."""
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
        ip = ipaddress.ip_address(args.ip)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if ip in net:
        print(f"  ✅ {ip} is within {net}")
    else:
        print(f"  ❌ {ip} is NOT within {net}")
    sys.exit(0 if ip in net else 1)


def cmd_range(args):
    """Find the smallest CIDR block(s) covering an IP range."""
    try:
        start = ipaddress.ip_address(args.start)
        end = ipaddress.ip_address(args.end)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    nets = list(ipaddress.summarize_address_range(start, end))
    total = sum(n.num_addresses for n in nets)
    print(f"  Range: {start} - {end}")
    print(f"  Total addresses: {total:,}")
    print(f"  CIDR blocks ({len(nets)}):")
    for n in nets:
        print(f"    {n} ({n.num_addresses:,} addresses)")


def cmd_split(args):
    """Split a CIDR block into smaller subnets."""
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    target = args.into
    if target <= net.prefixlen:
        print(f"Error: target prefix /{target} must be larger than /{net.prefixlen}", file=sys.stderr)
        sys.exit(1)

    subnets = list(net.subnets(new_prefix=target))
    print(f"  Splitting {net} into /{target} subnets:")
    print(f"  Count: {len(subnets)}")
    limit = 32
    for i, s in enumerate(subnets[:limit]):
        usable = max(0, s.num_addresses - 2) if s.version == 4 and s.prefixlen < 31 else s.num_addresses
        print(f"    {s} ({usable:,} usable)")
    if len(subnets) > limit:
        print(f"    ... and {len(subnets) - limit} more")


def cmd_overlap(args):
    """Check if two CIDR blocks overlap."""
    try:
        a = ipaddress.ip_network(args.cidr1, strict=False)
        b = ipaddress.ip_network(args.cidr2, strict=False)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if a.overlaps(b):
        print(f"  ✅ {a} and {b} overlap")
        if a.subnet_of(b):
            print(f"     {a} is a subnet of {b}")
        elif b.subnet_of(a):
            print(f"     {b} is a subnet of {a}")
    else:
        print(f"  ❌ {a} and {b} do NOT overlap")
    sys.exit(0 if a.overlaps(b) else 1)


def cmd_summarize(args):
    """Summarize multiple CIDR blocks into minimal set."""
    nets = []
    for c in args.cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    collapsed = list(ipaddress.collapse_addresses(nets))
    total = sum(n.num_addresses for n in collapsed)
    print(f"  Input: {len(nets)} networks")
    print(f"  Summarized: {len(collapsed)} networks")
    print(f"  Total addresses: {total:,}")
    for n in collapsed:
        print(f"    {n}")


def main():
    parser = argparse.ArgumentParser(description="CIDR/subnet calculator")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="Analyze a CIDR block")
    p.add_argument("cidr")

    p = sub.add_parser("contains", help="Check IP membership in CIDR")
    p.add_argument("cidr")
    p.add_argument("ip")

    p = sub.add_parser("range", help="IP range to CIDR blocks")
    p.add_argument("start")
    p.add_argument("end")

    p = sub.add_parser("split", help="Split CIDR into smaller subnets")
    p.add_argument("cidr")
    p.add_argument("--into", type=int, required=True, help="Target prefix length")

    p = sub.add_parser("overlap", help="Check if two CIDRs overlap")
    p.add_argument("cidr1")
    p.add_argument("cidr2")

    p = sub.add_parser("summarize", help="Collapse CIDRs into minimal set")
    p.add_argument("cidrs", nargs="+")

    args = parser.parse_args()
    {"info": cmd_info, "contains": cmd_contains, "range": cmd_range,
     "split": cmd_split, "overlap": cmd_overlap, "summarize": cmd_summarize}[args.command](args)


if __name__ == "__main__":
    main()
