"""Offline NIC/TUN scenario evidence classifier. Stdlib only; use python -I."""
import argparse
import ipaddress
import json
import re
import struct
import sys
from datetime import datetime
from pathlib import Path

def domain_inventory(source=None):
    source = source or Path(__file__).resolve().parents[2] / 'internal/engine/config.go'
    text = source.read_text(encoding='utf-8')
    def values(symbol):
        match = re.search(r'var\s+' + symbol + r'\s*=\s*\[\]string\s*\{([^}]+)\}', text)
        if not match:
            raise ValueError('Engine domain inventory unavailable')
        return tuple(re.findall(r'"([^"\n]+)"', re.sub(r'//[^\n]*', '', match[1])))
    return values('DiscordDomains'), values('DiscordHosts')


DOMAINS, HOSTS = domain_inventory()
MAX_BLOCK = 32 * 1024 * 1024
MAX_STREAM = 256 * 1024


class ParseError(ValueError):
    pass


def discord(name):
    name = name.lower().rstrip('.')
    return name in HOSTS or any(name == d or name.endswith('.' + d) for d in DOMAINS)


def exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise ParseError('Truncated capture structure')
    return b


def options(data, endian):
    result = {}
    while data:
        if len(data) < 4:
            raise ParseError('Short pcapng option')
        code, size = struct.unpack(endian + 'HH', data[:4])
        if code == 0:
            break
        if 4 + ((size + 3) & ~3) > len(data):
            raise ParseError('Truncated pcapng option')
        result[code] = data[4:4 + size]
        data = data[4 + ((size + 3) & ~3):]
    return result


def packets(path, detailed=False):
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
                sec, sub, cap, orig = struct.unpack(e + 'IIII', h)
                if cap > MAX_BLOCK or cap > snap or cap > orig:
                    raise ParseError('Invalid pcap packet length')
                frame = exact(f, cap)
                yield (dict(link=link, frame=frame, original=orig, interface=0,
                            timestamp=sec + sub / (1e9 if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6),
                            direction=0) if detailed else (link, frame, orig))
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
                    opts = options(b[8:], e)
                    resolution = opts.get(9, b'\x06')[0]
                    scale = (2 ** -(resolution & 127)) if resolution & 128 else 10 ** -resolution
                    offset = struct.unpack(e + 'q', opts[14])[0] if 14 in opts else 0
                    interfaces.append((link, snap, scale, offset))
                elif kind in (2, 6):
                    if len(b) < 20:
                        raise ParseError('Short packet block')
                    idx = struct.unpack(e + ('H' if kind == 2 else 'I'), b[:2 if kind == 2 else 4])[0]
                    cap, orig = struct.unpack(e + 'II', b[12:20])
                    if idx >= len(interfaces) or cap > orig or 20 + ((cap + 3) & ~3) > len(b):
                        raise ParseError('Invalid packet block')
                    link, snap, scale, offset = interfaces[idx]
                    if snap and cap > snap:
                        raise ParseError('Packet exceeds snaplen')
                    opts = options(b[20 + ((cap + 3) & ~3):], e)
                    flags = struct.unpack(e + 'I', opts.get(2, b'\0' * 4))[0]
                    if (kind == 2 and struct.unpack(e + 'H', b[2:4])[0] not in (0, 65535)) or (4 in opts and any(opts[4])) or flags & 0xffff0000:
                        raise ParseError('Packet drops or receive errors detected')
                    high, low = struct.unpack(e + 'II', b[4:12])
                    yield (dict(link=link, frame=b[20:20 + cap], original=orig, interface=idx,
                                timestamp=((high << 32) | low) * scale + offset,
                                direction=flags & 3) if detailed else (link, b[20:20 + cap], orig))
                elif kind == 5:
                    if len(b) < 12:
                        raise ParseError('Short interface statistics')
                    stats = options(b[12:], e)
                    if any(any(stats.get(code, b'')) for code in (5, 7)):
                        raise ParseError('Interface drops detected')
                elif kind == 3:
                    if len(b) < 4 or not interfaces:
                        raise ParseError('Invalid simple packet block')
                    orig = struct.unpack(e + 'I', b[:4])[0]
                    link, snap, _, _ = interfaces[0]
                    cap = min(orig, snap or orig)
                    if len(b) != 4 + ((cap + 3) & ~3):
                        raise ParseError('Invalid simple packet length')
                    yield (dict(link=link, frame=b[4:4 + cap], original=orig, interface=0,
                                timestamp=None, direction=0) if detailed else (link, b[4:4 + cap], orig))
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
        if ihl < 20 or length < ihl or len(b) < length:
            return None
        src, dst = (str(ipaddress.ip_address(x)) for x in (b[12:16], b[16:20]))
        frag = int.from_bytes(b[6:8], 'big') & 0x3fff
        return 4, src, dst, b[9], b[ihl:length], bool(frag)
    if kind == 0x86dd:
        if len(b) < 40 or b[0] >> 4 != 6:
            return None
        src, dst = (str(ipaddress.ip_address(x)) for x in (b[8:24], b[24:40]))
        end = 40 + int.from_bytes(b[4:6], 'big')
        if len(b) < end:
            return None
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
                frag = True  # Includes atomic fragments: this parser does not certify fragments.
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


def analyze(path, metadata=None, local_ips=(), private=False):
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
        if private:
            return ip
        return '<local>' if not locals_ or ip in locals_ else ip

    r = dict(total_packets=0, wireguard_packets=0, ipv6_packets=0, ipv6_noise_packets=0,
             truncated_packets=0, non_ip_packets=0, fragmented_packets=0,
             dns_queries=[], tls_sni=[], http_hosts=[], quic_flows=[], indicators=[])
    streams, quic, seen = {}, {}, set()

    def emit(kind, name, src, dst, sport, dport, wg, proto=6):
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
                     dst_port=dport, proto=proto, discord=is_discord, wireguard=wg)
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
                        emit('dns_queries', name, src, dst, sport, dport, wg, proto=17)
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
    r['result'] = 'INCONCLUSIVE'
    r['exit_code'] = 0  # Analysis ran; never a security exit status.
    return r


def epoch(value):
    return float(value) if isinstance(value, (int, float)) else datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def json_lines(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]


def executable_inventory(source=None):
    source = source or Path(__file__).with_name('executable_manifest.json')
    data = json.loads(source.read_text(encoding='utf-8-sig'))
    if data.get('version') != 1 or not data.get('roots') or not data.get('path_regex'):
        raise ValueError('Executable manifest unavailable')
    re.compile(data['path_regex'])
    return data


EXECUTABLE_MANIFEST = executable_inventory()


def protected(exe, inventory=None):
    exe = exe.replace('/', '\\')
    if any(part in ('.', '..') for part in exe.split('\\')):
        return False
    return bool(re.search((inventory or EXECUTABLE_MANIFEST)['path_regex'], exe))


def analyze_run(manifest_path, review=None):
    """Private evidence report. Review is explicit supplementary evidence, never inferred."""
    root = manifest_path.resolve().parent
    meta = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    review = review or {}
    issues, leaks, flows = set(), [], []
    inventory = meta.get('executable_manifest')
    if inventory != EXECUTABLE_MANIFEST:
        issues.add('executable_manifest_missing_or_mismatched')
        inventory = EXECUTABLE_MANIFEST
    snapshots = json_lines(root / 'snapshots.jsonl')
    controls = json_lines(root / 'controls.jsonl') if (root / 'controls.jsonl').exists() else []
    if not meta.get('capture_complete'):
        issues.add('incomplete_capture')
    if not snapshots:
        issues.add('missing_process_inventory')
    if not meta.get('started') or not meta.get('ended'):
        issues.add('missing_run_window')
    # An explicit capture-owned operator marker attests policy applied + tunnel up.
    activation = None
    marker = meta.get('activation', {})
    try:
        boundary = epoch(marker['time'])
        if (marker.get('source') == 'capture_operator_confirmation'
                and marker.get('policy_applied') is True and marker.get('tunnel_up') is True
                and epoch(meta['started']) <= boundary <= epoch(meta['ended'])):
            activation = boundary
    except (KeyError, TypeError, ValueError, OverflowError):
        pass
    if activation is None:
        issues.add('verified_activation_boundary_missing')
    if meta.get('scenario') not in ['L' + str(i) for i in range(1, 15)]:
        issues.add('unknown_scenario')
    if meta.get('scenario') in ('L9', 'L10'):
        issues.add('external_continuity_not_analyzed')
    for field in ('loss_checked', 'coverage_checked', 'scenario_stimulus_observed', 'encrypted_metadata_checked', 'outer_correlation_checked'):
        if review.get(field) is not True:
            issues.add(field + '_not_reviewed')
    if review.get('capture_loss', True):
        issues.add('capture_loss_or_unknown')
    if meta.get('inventory_errors'):
        issues.add('inventory_errors')
    for prev, cur in zip(snapshots, snapshots[1:]):
        if not 0 < epoch(cur['time']) - epoch(prev['time']) <= meta.get('max_snapshot_gap', 5):
            issues.add('snapshot_gap')
    if snapshots and meta.get('started') and meta.get('ended'):
        if (epoch(snapshots[0]['time']) - epoch(meta['started']) > meta.get('max_snapshot_gap', 5)
                or epoch(meta['ended']) - epoch(snapshots[-1]['time']) > meta.get('max_snapshot_gap', 5)):
            issues.add('inventory_window_gap')
    interfaces = meta.get('interfaces', [])
    physical = {int(i['if_index']) for i in interfaces if i['kind'] == 'physical'}
    for snapshot in snapshots:
        if not set(snapshot['active_physical']).issubset(physical):
            issues.add('physical_interface_not_captured')
    if not physical or not any(i['kind'] == 'tun' for i in interfaces):
        issues.add('missing_physical_or_tun')
    peers = [(epoch(s['time']), s.get('peer')) for s in snapshots]
    if any(not p for _, p in peers):
        issues.add('missing_runtime_peer')

    def owner(time, proto, src, sport, dst, dport):
        # Use both neighbouring samples, bounded in time. PID reuse is distinguished by start time.
        candidates = {}
        for snap in snapshots:
            if abs(epoch(snap['time']) - time) > meta.get('max_snapshot_gap', 5):
                continue
            procs = {int(p['pid']): p for p in snap['processes']}
            for sock in snap['sockets']:
                if sock['proto'] != proto or int(sock['local_port']) != sport or sock['local_ip'] not in (src, '0.0.0.0', '::'):
                    continue
                if proto == 6 and (sock['remote_ip'], int(sock['remote_port'])) != (dst, dport):
                    continue
                p = procs.get(int(sock['pid']))
                if p and p.get('exe') and p.get('started') and epoch(p['started']) <= time:
                    candidates[(p['pid'], p['started'])] = p
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    for iface in interfaces:
        files = iface.get('pcapng', [])
        if not files:
            issues.add('interface_capture_missing')
        count = 0
        for filename in iface.get('drops_pcapng', []):
            try:
                if any(packets(root / filename)):
                    issues.add('packet_drops')
            except (OSError, ValueError, struct.error):
                issues.add('invalid_drop_capture')
        if not iface.get('drops_pcapng'):
            issues.add('drop_evidence_missing')
        for filename in files:
            try:
                indicators = analyze(root / filename, {'local_ips': iface['local_ips']}, private=True)
                named = {(x['src'], x['src_port'], x['dst'], x['dst_port'], x['proto']) for x in indicators['indicators']}
                if any('skipped' in w or 'gap' in w or 'limit reached' in w for w in indicators['warnings']):
                    issues.add('protocol_parse_gap')
                for packet in packets(root / filename, detailed=True):
                    count += 1
                    if len(packet['frame']) < packet['original']:
                        issues.add('truncation')
                    if packet['timestamp'] is None:
                        issues.add('missing_timestamp')
                        continue
                    if packet['link'] != 1:
                        issues.add('unsupported_linktype')
                        continue
                    net = network(packet['frame'])
                    if not net:
                        # ARP is normal; other unparsed packets cannot prove absence.
                        if packet['frame'][12:14] != b'\x08\x06':
                            issues.add('unparsed_network_packet')
                        continue
                    version, src, dst, proto, data, fragment = net
                    if fragment:
                        issues.add('fragments')
                        continue
                    direction = ('out' if src in iface['local_ips'] else 'in' if dst in iface['local_ips'] else 'unknown')
                    if direction == 'unknown':
                        issues.add('unknown_direction')
                    if packet['direction'] in (1, 2) and direction != ('in' if packet['direction'] == 1 else 'out'):
                        issues.add('direction_disagreement')
                    if proto not in (6, 17):
                        if not (proto == 58 and data and data[0] in (130, 131, 132, 133, 134, 135, 136, 137, 143)):
                            issues.add('unattributed_non_transport')
                        continue
                    if len(data) < (20 if proto == 6 else 8):
                        issues.add('short_transport')
                        continue
                    sport, dport = struct.unpack('!HH', data[:4])
                    offset = (data[12] >> 4) * 4 if proto == 6 else 8
                    if offset < (20 if proto == 6 else 8) or offset > len(data) or (proto == 17 and int.from_bytes(data[4:6], 'big') != len(data)):
                        issues.add('malformed_transport')
                        continue
                    timestamp = packet['timestamp']
                    if meta.get('started') and meta.get('ended') and not epoch(meta['started']) <= timestamp <= epoch(meta['ended']):
                        issues.add('packet_outside_run_window')
                    if not snapshots or min(abs(epoch(s['time']) - timestamp) for s in snapshots) > meta.get('max_snapshot_gap', 5):
                        issues.add('packet_inventory_gap')
                    peer = next((p for t, p in reversed(peers) if t <= timestamp), None)
                    wg = bool(proto == 17 and peer and dst == peer['ip'] and dport == int(peer['port']) and data[8:12] == b'\x04\0\0\0' and len(data) >= 40)
                    process = owner(timestamp, proto, src, sport, dst, dport) if direction == 'out' else owner(timestamp, proto, dst, dport, src, sport)
                    f = dict(id=len(flows), time=timestamp, if_index=iface['if_index'], kind=iface['kind'],
                             phase='unverified' if activation is None else 'baseline' if timestamp < activation else 'protected',
                             direction=direction, direction_basis='interface_address_inventory', pcapng_direction=packet['direction'],
                             src=src, dst=dst, sport=sport, dport=dport, proto=proto, process=process,
                             wireguard_transport_candidate=wg, control_nonce=None)
                    for c in controls:
                        if (proto == 17 and src == c['local_ip'] and sport == c['local_port'] and dst == c['remote_ip'] and dport == c['remote_port']
                                and data[8:] == c['nonce'].encode('ascii') and epoch(c['started']) <= timestamp <= epoch(c['ended'])):
                            f['control_nonce'] = c['nonce']
                    flows.append(f)
                    if direction == 'out' and not process:
                        issues.add('unattributed_' + ('physical' if iface['kind'] == 'physical' else 'tun') + '_flow')
                    if iface['kind'] != 'physical' or direction != 'out':
                        continue
                    if activation is None or timestamp < activation:
                        continue  # Retain baseline evidence; it is not a post-activation leak.
                    related = (src, sport, dst, dport, proto) in named or review.get('flow_labels', {}).get(str(f['id'])) == 'discord'
                    if process and protected(process['exe'], inventory):
                        leaks.append(f['id'])
                    elif not process:
                        issues.add('unattributed_physical_flow')
                    elif wg:
                        continue  # Candidate only; explicit outer/receiver review still required.
                    elif related:
                        leaks.append(f['id'])
                    elif not f['control_nonce'] and review.get('flow_labels', {}).get(str(f['id'])) != 'unrelated':
                        issues.add('opaque_flow_requires_telemetry')
            except (OSError, ValueError, KeyError, struct.error):
                issues.add('capture_parse_error_or_drops')
        if not count:
            issues.add('empty_interface_capture')

    for mode in ('direct', 'tunnel'):
        valid = False
        for c in controls:
            if c['mode'] != mode:
                continue
            matching = [f for f in flows if f['control_nonce'] == c['nonce'] and f['direction'] == 'out' and f['phase'] == 'protected']
            expected = 'physical' if mode == 'direct' else 'tun'
            observed = [f for f in matching if f['kind'] == expected and f['process'] and f['process']['pid'] == c['pid'] and f['process']['started'] == c['process_started'] and not protected(f['process']['exe'], inventory)]
            if mode == 'tunnel' and any(f['kind'] == 'physical' for f in matching):
                leaks.extend(f['id'] for f in matching if f['kind'] == 'physical')
            outer = any(f['kind'] == 'physical' and f['direction'] == 'out' and f['wireguard_transport_candidate'] and epoch(c['started']) <= f['time'] <= epoch(c['ended']) for f in flows)
            # Receiver telemetry binds the nonce to the remote observation; concurrent WG UDP alone cannot.
            receipt = review.get('tunnel_receipts', {}).get(c['nonce'], {})
            correlation = receipt.get('received_via_tunnel') is True and bool(receipt.get('evidence'))
            if observed and (mode == 'direct' or (outer and correlation and not any(f['kind'] == 'physical' for f in matching))):
                valid = True
        if not valid:
            issues.add(mode + '_positive_control_missing')
    # Quality gates take precedence; confirmed leak records are retained even on an incomplete run.
    return dict(scenario=meta.get('scenario'), result='INCONCLUSIVE' if issues else 'FAIL' if leaks else 'PASS',
                scope='verified activation boundary through run end only', activation=activation,
                baseline=[f['id'] for f in flows if f['phase'] == 'baseline'],
                issues=sorted(issues), leaks=sorted(set(leaks)), flows=flows, exit_code=0)


def redacted(report):
    # Allowlist only enums and counts: no free text, addresses, exe paths, usernames or nonces.
    return dict(scenario=report['scenario'] if report['scenario'] in ['L' + str(i) for i in range(1, 15)] else 'unknown',
                result=report['result'], packet_records=len(report['flows']), confirmed_leaks=len(report['leaks']),
                baseline_records=len(report['baseline']),
                issues=report['issues'], exit_code=0)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path, help='Private run.json manifest')
    p.add_argument('--review', type=Path, help='Private operator review/telemetry JSON')
    p.add_argument('--export', type=Path, help='Separate allowlisted redacted JSON')
    p.add_argument('--json', type=Path, help='Private report; default beside run.json')
    args = p.parse_args(argv)
    output = args.json or args.capture.with_suffix('.report.json')
    try:
        repo = Path(__file__).resolve().parents[2]
        targets = [args.capture, output] + ([args.export] if args.export else [])
        if any(t.resolve() == repo or repo in t.resolve().parents for t in targets):
            raise ParseError('Private evidence must be outside repository')
        if output.resolve() == args.capture.resolve() or (args.review and output.resolve() == args.review.resolve()):
            raise ParseError('Output would overwrite input')
        if args.export and (args.export.resolve() in (args.capture.resolve(), output.resolve()) or (args.review and args.export.resolve() == args.review.resolve())):
            raise ParseError('Export would overwrite input')
        if output.exists() or (args.export and args.export.exists()):
            raise ParseError('Refusing to overwrite existing evidence')
        review = json.loads(args.review.read_text(encoding='utf-8-sig')) if args.review else {}
        report = analyze_run(args.capture, review)
        output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
        if args.export:
            args.export.write_text(json.dumps(redacted(report), indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error):
        # Do not echo exceptions: attacker-controlled bytes, paths or raw IPs may be present.
        print('Parse error: invalid/unreadable capture or metadata, or report write failed.', file=sys.stderr)
        return 1
    print(json.dumps(redacted(report)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
