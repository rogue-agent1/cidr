#!/usr/bin/env python3
"""cidr - CIDR/subnet calculator and IP range tool.

One file. Zero deps. Knows your subnets.

Usage:
  cidr.py info 192.168.1.0/24       → subnet details
  cidr.py contains 10.0.0.0/8 10.0.1.5  → check membership
  cidr.py range 192.168.1.0/28      → list all IPs
  cidr.py split 10.0.0.0/16 24      → split into /24s
  cidr.py merge 10.0.0.0/24 10.0.1.0/24  → merge adjacent
  cidr.py overlap 10.0.0.0/16 10.0.1.0/24  → check overlap
"""

import argparse
import ipaddress
import json
import sys


def cmd_info(args):
    net = ipaddress.ip_network(args.cidr, strict=False)
    info = {
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address) if net.version == 4 else None,
        "netmask": str(net.netmask),
        "hostmask": str(net.hostmask),
        "prefix": net.prefixlen,
        "hosts": net.num_addresses - 2 if net.version == 4 and net.prefixlen < 31 else net.num_addresses,
        "total_addresses": net.num_addresses,
        "version": net.version,
        "is_private": net.is_private,
        "first_host": str(list(net.hosts())[0]) if net.num_addresses > 2 else str(net.network_address),
        "last_host": str(list(net.hosts())[-1]) if net.num_addresses > 2 else str(net.broadcast_address),
    }
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        for k, v in info.items():
            print(f"  {k:18s} {v}")


def cmd_contains(args):
    net = ipaddress.ip_network(args.cidr, strict=False)
    ip = ipaddress.ip_address(args.ip)
    if ip in net:
        print(f"✅ {args.ip} is in {args.cidr}")
    else:
        print(f"❌ {args.ip} is NOT in {args.cidr}")
        return 1
    return 0


def cmd_range(args):
    net = ipaddress.ip_network(args.cidr, strict=False)
    limit = args.limit or 256
    for i, ip in enumerate(net.hosts()):
        if i >= limit:
            print(f"  ... ({net.num_addresses - 2 - limit} more)")
            break
        print(str(ip))


def cmd_split(args):
    net = ipaddress.ip_network(args.cidr, strict=False)
    new_prefix = int(args.prefix)
    if new_prefix <= net.prefixlen:
        print(f"New prefix /{new_prefix} must be larger than /{net.prefixlen}", file=sys.stderr)
        return 1
    subnets = list(net.subnets(new_prefix=new_prefix))
    for s in subnets[:100]:
        hosts = s.num_addresses - 2 if s.version == 4 and s.prefixlen < 31 else s.num_addresses
        print(f"  {str(s):20s}  ({hosts} hosts)")
    if len(subnets) > 100:
        print(f"  ... ({len(subnets) - 100} more)")


def cmd_merge(args):
    nets = [ipaddress.ip_network(c, strict=False) for c in args.cidrs]
    merged = list(ipaddress.collapse_addresses(nets))
    for m in merged:
        print(str(m))


def cmd_overlap(args):
    a = ipaddress.ip_network(args.cidr1, strict=False)
    b = ipaddress.ip_network(args.cidr2, strict=False)
    if a.overlaps(b):
        print(f"✅ {args.cidr1} and {args.cidr2} overlap")
    else:
        print(f"❌ {args.cidr1} and {args.cidr2} do NOT overlap")
        return 1
    return 0


def main():
    p = argparse.ArgumentParser(description="CIDR/subnet calculator")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("info")
    s.add_argument("cidr")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("contains")
    s.add_argument("cidr")
    s.add_argument("ip")
    s.set_defaults(func=cmd_contains)

    s = sub.add_parser("range")
    s.add_argument("cidr")
    s.add_argument("--limit", type=int, default=256)
    s.set_defaults(func=cmd_range)

    s = sub.add_parser("split")
    s.add_argument("cidr")
    s.add_argument("prefix")
    s.set_defaults(func=cmd_split)

    s = sub.add_parser("merge")
    s.add_argument("cidrs", nargs="+")
    s.set_defaults(func=cmd_merge)

    s = sub.add_parser("overlap")
    s.add_argument("cidr1")
    s.add_argument("cidr2")
    s.set_defaults(func=cmd_overlap)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return 1
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
