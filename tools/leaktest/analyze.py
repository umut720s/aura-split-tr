"""Offline physical-NIC leak indicators. Python stdlib only; use python -I."""
import argparse
import ipaddress
import json
import re
import struct
import sys
from pathlib import Path

DOMAINS = ('discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net',
           'discord.media', 'discordcdn.com', 'discordsays.com', 'dis.gd',
           'discord.gift', 'discord.dev', 'discordstatus.com', 'discord.co', 'discord.new')
MAX_BLOCK = 32 * 1024 * 1024
MAX_STREAM = 256 * 1024


class ParseError(ValueError):
    pass


def discord(name):
    name = name.lower().rstrip('.')
    return any(name == d or name.endswith('.' + d) for d in DOMAINS)


def exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise ParseError('Truncated capture structure')
    return b


def packets(path):
    """Yield (linktype, captured bytes, original length), checking container bounds."""
    with open(path, 'rb') as f:
        magic = exact(f, 4)
        classic = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                   b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        if magic in classic:
            e = classic[magic]
            h = exact(f, 20)
            major, minor, _, _, snap, link = struct.unpack(e + 'HHIIII', h)
            if (major, minor) != (2, 4) or not snap:
                raise ParseError('Invalid pcap header')
            link &= 0xffff
            while True:
                h = f.read(16)
                if not h:
                    return
                if len(h) != 16:
                    raise ParseError('Truncated pcap record')
                _, _, cap, orig = struct.unpack(e + 'IIII', h)
                if cap > MAX_BLOCK or cap > snap or cap > orig:
                    raise ParseError('Invalid pcap packet length')
                yield link, exact(f, cap), orig
        elif magic == b'\x0a\x0d\x0d\x0a':
            f.seek(0)
            e, interfaces = None, []
            while True:
                h = f.read(8)
                if not h:
                    return
                if len(h) != 8:
                    raise ParseError('Truncated pcapng header')
                section = h[:4] == b'\x0a\x0d\x0d\x0a'
                if section:
                    bom = exact(f, 4)
                    if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                        raise ParseError('Invalid pcapng byte order')
                    e = '<' if bom[0] == 0x4d else '>'
                if e is None:
                    raise ParseError('Missing pcapng section')
                kind, size = struct.unpack(e + 'II', h)
                if size < (28 if section else 12) or size % 4 or size > MAX_BLOCK:
                    raise ParseError('Invalid pcapng block size')
                rest = (bom if section else b'') + exact(f, size - (12 if section else 8))
                if struct.unpack(e + 'I', rest[-4:])[0] != size:
                    raise ParseError('pcapng block length mismatch')
                b = rest[:-4]
                if section:
                    if struct.unpack(e + 'H', b[4:6])[0] != 1:
                        raise ParseError('Unsupported pcapng version')
                    interfaces = []
                elif kind == 1:
                    if len(b) < 8:
                        raise ParseError('Short interface block')
                    link, _, snap = struct.unpack(e + 'HHI', b[:8])
                    interfaces.append((link, snap))
                elif kind in (2, 6):
                    if len(b) < 20:
                        raise ParseError('Short packet block')
                    idx = struct.unpack(e + ('H' if kind == 2 else 'I'), b[:2 if kind == 2 else 4])[0]
                    cap, orig = struct.unpack(e + 'II', b[12:20])
                    if idx >= len(interfaces) or cap > orig or 20 + ((cap + 3) & ~3) > len(b):
                        raise ParseError('Invalid packet block')
                    link, snap = interfaces[idx]
                    if snap and cap > snap:
                        raise ParseError('Packet exceeds snaplen')
                    yield link, b[20:20 + cap], orig
                elif kind == 3:
                    if len(b) < 4 or not interfaces:
                        raise ParseError('Invalid simple packet block')
                    orig = struct.unpack(e + 'I', b[:4])[0]
                    link, snap = interfaces[0]
                    cap = min(orig, snap or orig)
                    if len(b) != 4 + ((cap + 3) & ~3):
                        raise ParseError('Invalid simple packet length')
                    yield link, b[4:4 + cap], orig
        else:
            raise ParseError('Unknown capture format')


def network(frame):
    if len(frame) < 14:
        return None
    kind, pos = struct.unpack('!H', frame[12:14])[0], 14
    while kind in (0x8100, 0x88a8, 0x9100):
        if pos + 4 > len(frame):
            return None
        kind = struct.unpack('!H', frame[pos + 2:pos + 4])[0]
        pos += 4
    b = frame[pos:]
    if kind == 0x0800:
        if len(b) < 20 or b[0] >> 4 != 4:
            return None
        ihl = (b[0] & 15) * 4
        length = int.from_bytes(b[2:4], 'big')
        if ihl < 20 or length < ihl or len(b) < ihl:
            return None
        src, dst = (str(ipaddress.ip_address(x)) for x in (b[12:16], b[16:20]))
        frag = int.from_bytes(b[6:8], 'big') & 0x3fff
        return 4, src, dst, b[9], b[ihl:length], bool(frag)
    if kind == 0x86dd:
        if len(b) < 40 or b[0] >> 4 != 6:
            return None
        src, dst = (str(ipaddress.ip_address(x)) for x in (b[8:24], b[24:40]))
        end = 40 + int.from_bytes(b[4:6], 'big')
        b = b[:end]
        proto, pos, frag = b[6], 40, False
        for _ in range(16):
            if proto not in (0, 43, 44, 51, 60):
                return 6, src, dst, proto, b[pos:], frag
            if pos + 2 > len(b):
                return None
            nxt = b[pos]
            size = 8 if proto == 44 else ((b[pos + 1] + 2) * 4 if proto == 51 else (b[pos + 1] + 1) * 8)
            if pos + size > len(b):
                return None
            if proto == 44:
                frag = bool(int.from_bytes(b[pos + 2:pos + 4], 'big') & 0xfff9)
            proto, pos = nxt, pos + size
    return None


def dns_queries(b):
    if len(b) < 12 or b[2] & 0x80:
        return []
    count = int.from_bytes(b[4:6], 'big')
    pos, names = 12, []

    def name_at(start):
        labels, seen, p, end = [], set(), start, None
        while True:
            if p >= len(b) or p in seen:
                raise ValueError('Incomplete DNS name')
            seen.add(p)
            n = b[p]
            if n & 0xc0 == 0xc0:
                if p + 1 >= len(b):
                    raise ValueError('Incomplete DNS pointer')
                end = end or p + 2
                p = ((n & 63) << 8) | b[p + 1]
                continue
            if n > 63 or p + 1 + n > len(b):
                raise ValueError('Invalid DNS label')
            p += 1
            if n == 0:
                return '.'.join(labels), end or p
            labels.append(b[p:p + n].decode('ascii', 'replace'))
            p += n
            if len(seen) > 255:
                raise ValueError('DNS name too long')

    for _ in range(min(count, 1024)):
        name, pos = name_at(pos)
        if pos + 4 > len(b):
            raise ValueError('Incomplete DNS question')
        pos += 4
        names.append(name)
    return names


def hello_names(b):
    """Read SNI from available complete extensions, even with snaplen truncation."""
    if len(b) < 35 or b[0] != 1:
        return []
    end = min(len(b), 4 + int.from_bytes(b[1:4], 'big'))
    pos = 38  # handshake header + version + random
    if pos >= end:
        return []
    pos += 1 + b[pos]
    if pos + 2 > end:
        return []
    pos += 2 + int.from_bytes(b[pos:pos + 2], 'big')
    if pos >= end:
        return []
    pos += 1 + b[pos]
    if pos + 2 > end:
        return []
    limit = min(end, pos + 2 + int.from_bytes(b[pos:pos + 2], 'big'))
    pos += 2
    names = []
    while pos + 4 <= limit:
        kind, size = struct.unpack('!HH', b[pos:pos + 4])
        pos += 4
        if pos + size > limit:
            break
        ext = b[pos:pos + size]
        if kind == 0 and len(ext) >= 2:
            p, stop = 2, min(len(ext), 2 + int.from_bytes(ext[:2], 'big'))
            while p + 3 <= stop:
                typ, n = ext[p], int.from_bytes(ext[p + 1:p + 3], 'big')
                p += 3
                if p + n > stop:
                    break
                if typ == 0:
                    names.append(ext[p:p + n].decode('ascii', 'replace'))
                p += n
        pos += size
    return names


def tls_names(b):
    pos, hs = 0, bytearray()
    while pos + 5 <= len(b):
        if b[pos] != 22 or b[pos + 1] != 3:
            break
        n = int.from_bytes(b[pos + 3:pos + 5], 'big')
        hs.extend(b[pos + 5:pos + 5 + n])
        pos += 5 + n
    return hello_names(bytes(hs))


def http_names(b):
    # Only request headers; never scan bodies for a Host-looking string.
    if not re.match(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|PATCH|TRACE) \S+ HTTP/1\.[01]\r\n', b):
        return []
    headers = b.split(b'\r\n\r\n', 1)[0]
    return [m.decode('ascii', 'replace').strip().split(':', 1)[0]
            for m in re.findall(rb'(?im)^Host:[ \t]*([^\r\n]+)\r\n', headers + b'\r\n')]


def analyze(path, metadata=None, local_ips=()):
    meta = metadata or {}
    locals_ = {str(ipaddress.ip_address(x)) for x in [*meta.get('local_ips', []), *local_ips]}
    ep = meta.get('wireguard_endpoint')
    if ep:
        ep = (str(ipaddress.ip_address(ep['ip'])), int(ep['port']))
        if not 1 <= ep[1] <= 65535:
            raise ParseError('Invalid endpoint port')
    warnings = set()
    if not locals_:
        warnings.add('Local IP inventory absent: ALL IP addresses masked; supply metadata or --local-ip.')
    if not ep:
        warnings.add('WireGuard endpoint absent: no endpoint flow whitelisted.')
    if meta.get('capture_complete') is False:
        warnings.add('Capture metadata marks this run incomplete.')

    def mask(ip):
        return '<local>' if not locals_ or ip in locals_ else ip

    r = dict(total_packets=0, wireguard_packets=0, ipv6_packets=0, ipv6_noise_packets=0,
             truncated_packets=0, non_ip_packets=0, fragmented_packets=0,
             dns_queries=[], tls_sni=[], http_hosts=[], quic_flows=[], indicators=[])
    streams, quic, seen = {}, {}, set()

    def emit(kind, name, src, dst, sport, dport, wg):
        name = name.lower().rstrip('.')
        key = kind, name, src, dst, sport, dport, wg
        if key in seen:
            return
        seen.add(key)
        is_discord = discord(name)
        # Host/SNI fields can themselves be IP literals. Do not expose local IPs there.
        if locals_:
            for ip in sorted(locals_, key=len, reverse=True):
                name = name.replace(ip, '<local>')
        else:
            try:
                ipaddress.ip_address(name.strip('[]'))
                name = '<local>'
            except ValueError:
                pass
        entry = dict(name=name, src=mask(src), dst=mask(dst), src_port=sport,
                     dst_port=dport, discord=is_discord, wireguard=wg)
        r[kind].append(entry)
        if entry['discord'] and not wg:
            r['indicators'].append(dict(kind=kind, **entry))

    for link, frame, original in packets(path):
        r['total_packets'] += 1
        if len(frame) < original:
            r['truncated_packets'] += 1
        if link != 1:
            raise ParseError('Unsupported link type (Ethernet required)')
        net = network(frame)
        if not net:
            r['non_ip_packets'] += 1
            continue
        version, src, dst, proto, b, frag = net
        if version == 6:
            # ND/MLD/RS/RA on local links are counted separately, not all IPv6 multicast traffic.
            noise = (proto == 58 and b and b[0] in (130, 131, 132, 133, 134, 135, 136, 137, 143)
                     and (ipaddress.ip_address(src).is_link_local or src == '::')
                     and (ipaddress.ip_address(dst).is_multicast or ipaddress.ip_address(dst).is_link_local))
            r['ipv6_noise_packets' if noise else 'ipv6_packets'] += 1
        if frag:
            r['fragmented_packets'] += 1
            continue
        if proto not in (6, 17) or len(b) < (20 if proto == 6 else 8):
            continue
        sport, dport = struct.unpack('!HH', b[:4])
        wg = proto == 17 and ep is not None and ((src, sport) == ep or (dst, dport) == ep)
        if wg:
            r['wireguard_packets'] += 1
            continue  # WireGuard ciphertext must not be interpreted as DNS/HTTP/TLS.
        if proto == 17:
            length = int.from_bytes(b[4:6], 'big')
            if length < 8:
                warnings.add('Malformed UDP header skipped.')
                continue
            data = b[8:length]
            if 53 in (sport, dport):
                try:
                    for name in dns_queries(data):
                        emit('dns_queries', name, src, dst, sport, dport, wg)
                except ValueError:
                    warnings.add('Incomplete or malformed DNS query skipped.')
            if dport == 443:
                key = src, dst, sport, dport
                quic[key] = quic.get(key, 0) + 1
            continue
        offset = (b[12] >> 4) * 4
        if offset < 20 or offset > len(b):
            warnings.add('Incomplete or malformed TCP header skipped.')
            continue
        seq = int.from_bytes(b[4:8], 'big')
        if b[13] & 2:
            seq = (seq + 1) & 0xffffffff
        key = src, dst, sport, dport
        if b[13] & 2:
            streams.pop(key, None)
        data = b[offset:]
        if not data:
            continue
        if key not in streams:
            if len(streams) >= 4096:
                warnings.add('TCP flow limit reached; some flows skipped.')
                continue
            streams[key] = []
        parts = streams[key]
        if sum(len(p[1]) for p in parts) + len(data) <= MAX_STREAM and len(parts) < 2048:
            parts.append((seq, data))
        else:
            warnings.add('TCP reassembly limit reached; some bytes skipped.')

    for (src, dst, sport, dport), parts in streams.items():
        # Relative sequence numbers handle wraparound within the bounded stream.
        base = parts[0][0]
        ordered = sorted((((s - base + 2**31) % 2**32 - 2**31, d) for s, d in parts))
        end, buf = ordered[0][0], bytearray()
        for seq, data in ordered:
            if seq > end:
                warnings.add('TCP sequence gap (often snaplen truncation); later bytes skipped.')
                break
            skip = end - seq
            if skip < len(data):
                buf.extend(data[skip:])
                end += len(data) - skip
        data = bytes(buf)
        if 53 in (sport, dport):
            pos = 0
            while pos + 2 <= len(data):
                n = int.from_bytes(data[pos:pos + 2], 'big')
                pos += 2
                if pos + n > len(data):
                    warnings.add('Incomplete DNS-over-TCP message skipped.')
                    break
                try:
                    for name in dns_queries(data[pos:pos + n]):
                        emit('dns_queries', name, src, dst, sport, dport, False)
                except ValueError:
                    warnings.add('Incomplete or malformed DNS query skipped.')
                pos += n
        for name in tls_names(data):
            emit('tls_sni', name, src, dst, sport, dport, False)
        for name in http_names(data):
            emit('http_hosts', name, src, dst, sport, dport, False)
    for (src, dst, sport, dport), count in sorted(quic.items()):
        r['quic_flows'].append(dict(src=mask(src), dst=mask(dst), src_port=sport,
                                    dst_port=dport, packets=count, sni='unparsed'))
    warnings.add('UDP 443 is a QUIC candidate only; QUIC SNI unparsed (stdlib has no AES).')
    warnings.add('No indicators is not proof of no leak: ECH, encrypted DNS, cached DNS, truncation, fragments and capture loss can hide names.')
    if not r['total_packets']:
        warnings.add('Empty capture: no usable negative evidence.')
    if not r['wireguard_packets']:
        warnings.add('No WireGuard endpoint packets observed; expected tunnel activity is unverified.')
    if r['truncated_packets']:
        warnings.add('Snaplen truncated packets: names beyond captured bytes cannot be inspected.')
    if r['fragmented_packets']:
        warnings.add('IP fragments counted but not reassembled.')
    r['warnings'] = sorted(warnings)
    r['exit_code'] = 2 if r['indicators'] else 0
    return r


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--metadata', type=Path, help='Default: capture basename + .json')
    p.add_argument('--local-ip', action='append', default=[], help='Local interface IP; repeatable')
    p.add_argument('--json', type=Path, help='Default: capture basename + .report.json')
    args = p.parse_args(argv)
    output = args.json or args.capture.with_suffix('.report.json')
    metadata = args.metadata or args.capture.with_suffix('.json')
    if output.resolve() in (args.capture.resolve(), metadata.resolve()):
        print('Parse error: report path would overwrite capture or metadata.', file=sys.stderr)
        return 1
    try:
        meta = json.loads(metadata.read_text(encoding='utf-8-sig')) if metadata.exists() else {}
        if args.metadata and not metadata.exists():
            raise ParseError('Requested metadata file is missing')
        report = analyze(args.capture, meta, args.local_ip)
        output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error):
        # Do not echo exceptions: attacker-controlled bytes, paths or raw IPs may be present.
        print('Parse error: invalid/unreadable capture or metadata, or report write failed.', file=sys.stderr)
        return 1
    print('Packets: {total_packets}; WireGuard: {wireguard_packets}; IPv6: {ipv6_packets}; IPv6 ND/MLD noise: {ipv6_noise_packets}; truncated: {truncated_packets}'.format(**report))
    for kind in ('dns_queries', 'tls_sni', 'http_hosts'):
        print('{}: {}'.format(kind, len(report[kind])))
        for item in report[kind]:
            # JSON escaping prevents names from injecting terminal controls or extra lines.
            print('  {} {} -> {}:{} {}'.format(json.dumps(item['name']), item['src'], item['dst'], item['dst_port'], 'DISCORD' if item['discord'] else ''))
    for flow in report['quic_flows']:
        print('UDP443 {} -> {}:443; packets={}; SNI unparsed'.format(flow['src'], flow['dst'], flow['packets']))
    for warning in report['warnings']:
        print('Warning: ' + warning)
    print('Discord leak indicators: {}; exit {}'.format(len(report['indicators']), report['exit_code']))
    print('JSON report written (capture directory by default).')
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
