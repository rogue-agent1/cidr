# cidr

IP/CIDR calculator and subnet toolkit.

## Usage

```bash
python3 cidr.py info 192.168.1.0/24       # full subnet info
python3 cidr.py contains 10.0.0.0/8 10.1.2.3  # containment check
python3 cidr.py split 10.0.0.0/8 2        # split into 4 /10s
python3 cidr.py range 192.168.1.0/28      # show IP range
python3 cidr.py overlap 10.0.0.0/24 10.0.0.128/25
python3 cidr.py supernet 10.1.0.0/16 10.2.0.0/16
```

## Features

- Subnet info (network, broadcast, mask, wildcard, usable hosts)
- IP containment check
- Subnet splitting
- IP range listing
- Overlap detection
- Supernet calculation
- RFC 1918 classification
- Zero dependencies
