"""Maintainer-owned remote UDP receiver. Logs are private; no TLS/WG keys."""
import argparse
import hashlib
import ipaddress
import json
import re
import socket
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', required=True, help='Literal receiver address')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--expected-tunnel-source', required=True, help='Independently verified VPN exit IP')
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    if args.out.resolve() == repo or repo in args.out.resolve().parents or args.out.exists():
        parser.error('Select a new private output outside repository')
    bind = ipaddress.ip_address(args.bind)
    expected = str(ipaddress.ip_address(args.expected_tunnel_source))
    records = []
    with socket.socket(socket.AF_INET6 if bind.version == 6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((str(bind), args.port))
        sock.settimeout(0.5)
        end = time.monotonic() + args.seconds
        while time.monotonic() < end:
            try:
                data, sender = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if re.fullmatch(rb'AURA-P0B-[0-9a-f]{32}', data):
                records.append(dict(time=time.time(), nonce=data.decode('ascii'), source=sender[0], port=sender[1]))
    digest = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    receipts = {r['nonce']: dict(received_via_tunnel=r['source'] == expected,
                               evidence='receiver-records-sha256:' + digest) for r in records}
    with args.out.open('x', encoding='utf-8') as output:
        json.dump(dict(records=records, tunnel_receipts=receipts), output, indent=2)
    print('Private receiver records saved; merge tunnel_receipts into the private operator review.')


if __name__ == '__main__':
    main()
