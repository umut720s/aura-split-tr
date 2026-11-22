"""Synthetic fixtures only: no network, real captures or third-party packages."""
import contextlib
import importlib.util
import io
import ipaddress
import json
import struct
import tempfile
import unittest
from pathlib import Path

# -I excludes the working directory from sys.path; load the adjacent module explicitly.
spec = importlib.util.spec_from_file_location('leak_analyze', Path(__file__).with_name('analyze.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
LOCAL = '192.0.2.10'
REMOTE = '198.51.100.9'
META = {'local_ips': [LOCAL], 'wireguard_endpoint': {'ip': REMOTE, 'port': 51820}}


def udp(data, sport=50000, dport=53):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data


def tcp(data, sport=50000, dport=443, seq=100, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, flags, 4096, 0, 0) + data


def eth(data, proto=17, src=LOCAL, dst=REMOTE, vlan=False, ipv6=False, fragment=False):
    if ipv6:
        net = struct.pack('!IHBB', 6 << 28, len(data), proto, 64)
        net += ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        typ = 0x86dd
    else:
        net = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(data), 1, 0x2000 if fragment else 0, 64, proto, 0)
        net += ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        typ = 0x0800
    header = b'\x11' * 6 + b'\x22' * 6
    header += struct.pack('!HHHHH', 0x88a8, 1, 0x8100, 2, typ) if vlan else struct.pack('!H', typ)
    return header + net + data


def dns(name='voice.discord.gg', response=False):
    return (struct.pack('!HHHHHH', 1, 0x8100 if response else 0x0100, 1, 0, 0, 0)
            + b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0\0\x01\0\x01')


def hello(name='gateway.discord.gg'):
    host = name.encode()
    names = b'\0' + struct.pack('!H', len(host)) + host
    sni = struct.pack('!H', len(names)) + names
    extensions = struct.pack('!HH', 0, len(sni)) + sni
    body = b'\x03\x03' + b'\0' * 32 + b'\0\0\x02\x13\x01\x01\0'
    body += struct.pack('!H', len(extensions)) + extensions
    return b'\x01' + len(body).to_bytes(3, 'big') + body


def record(h):
    return b'\x16\x03\x01' + struct.pack('!H', len(h)) + h


def pcap(frames, endian='<', nano=False, link=1):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    b = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 65535, link)
    for frame in frames:
        cap, orig = frame if isinstance(frame, tuple) else (frame, len(frame))
        b += struct.pack(endian + 'IIII', 0, 0, len(cap), orig) + cap
    return b


def block(kind, body, e='<'):
    body += b'\0' * ((-len(body)) % 4)
    n = len(body) + 12
    return struct.pack(e + 'II', kind, n) + body + struct.pack(e + 'I', n)


def pcapng(frames, e='<', packet_type=6, link=1):
    b = block(0x0a0d0d0a, struct.pack(e + 'IHHq', 0x1a2b3c4d, 1, 0, -1), e)
    b += block(1, struct.pack(e + 'HHI', link, 0, 65535), e)
    for frame in frames:
        if packet_type == 3:
            body = struct.pack(e + 'I', len(frame))
        elif packet_type == 2:
            body = struct.pack(e + 'HHIIII', 0, 0, 0, 0, len(frame), len(frame))
        else:
            body = struct.pack(e + 'IIIII', 0, 0, 0, len(frame), len(frame))
        b += block(packet_type, body + frame, e)
    return b


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        # All generated artifacts, including temporary captures, stay inside tools/leaktest.
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'synthetic.pcapng'

    def run_capture(self, frames, meta=META, fmt=pcapng):
        self.path.write_bytes(fmt(frames))
        return a.analyze(self.path, meta)

    def test_domain_boundaries_all_domains(self):
        for d in a.DOMAINS:
            self.assertTrue(a.discord(d.upper() + '.'))
            self.assertTrue(a.discord('cdn.' + d))
            self.assertFalse(a.discord(d + '.evil.example'))
            self.assertFalse(a.discord('evil' + d))

    def test_container_variants(self):
        frame = eth(udp(dns()))
        for e in ('<', '>'):
            for nano in (False, True):
                r = self.run_capture([frame], fmt=lambda f: pcap(f, e, nano))
                self.assertEqual(r['exit_code'], 2)
            for typ in (2, 3, 6):
                r = self.run_capture([frame], fmt=lambda f: pcapng(f, e, typ))
                self.assertEqual(r['total_packets'], 1)
                self.assertEqual(len(r['dns_queries']), 1)

    def test_multiple_pcapng_sections_reset_byte_order(self):
        f = eth(udp(dns()))
        self.path.write_bytes(pcapng([f]) + pcapng([f], '>'))
        self.assertEqual(a.analyze(self.path, META)['total_packets'], 2)

    def test_dns_udp_vlan_leak_and_no_response(self):
        r = self.run_capture([eth(udp(dns()), vlan=True), eth(udp(dns(response=True)))])
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(len(r['dns_queries']), 1)
        self.assertEqual(r['dns_queries'][0]['src'], '<local>')
        self.assertNotIn(LOCAL, json.dumps(r))

    def test_dns_compression_and_pointer_loop(self):
        msg = dns('discord.com')
        msg = msg[:4] + b'\0\x02' + msg[6:] + b'\xc0\x0c\0\x01\0\x01'
        self.assertEqual(a.dns_queries(msg), ['discord.com', 'discord.com'])
        loop = struct.pack('!HHHHHH', 1, 0, 1, 0, 0, 0) + b'\xc0\x0c\0\x01\0\x01'
        with self.assertRaises(ValueError):
            a.dns_queries(loop)

    def test_dns_tcp_split_out_of_order_retransmission(self):
        msg = dns('cdn.discordapp.com')
        data = struct.pack('!H', len(msg)) + msg
        packets = [eth(tcp(data[9:], dport=53, seq=109), proto=6),
                   eth(tcp(data[:9], dport=53, seq=100), proto=6),
                   eth(tcp(data[:9], dport=53, seq=100), proto=6)]
        r = self.run_capture(packets)
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(len(r['dns_queries']), 1)

    def test_tls_sni_any_port_split_record_and_tcp(self):
        h = hello()
        data = record(h[:25]) + record(h[25:])
        r = self.run_capture([eth(tcp(data[:31], dport=8443), proto=6),
                              eth(tcp(data[31:], dport=8443, seq=131), proto=6)])
        self.assertEqual(r['tls_sni'][0]['name'], 'gateway.discord.gg')
        self.assertEqual(r['exit_code'], 2)

    def test_tls_sequence_wraparound(self):
        data = record(hello())
        r = self.run_capture([eth(tcp(data[:20], seq=0xfffffff0), proto=6),
                              eth(tcp(data[20:], seq=4), proto=6)])
        self.assertEqual(r['exit_code'], 2)

    def test_http_host_and_no_body_false_positive(self):
        good = b'GET / HTTP/1.1\r\nHost: Discord.com:80\r\n\r\n'
        body = b'POST / HTTP/1.1\r\nHost: example.org\r\n\r\nHost: discord.com\r\n'
        r = self.run_capture([eth(tcp(good, dport=80), proto=6),
                              eth(tcp(body, sport=50001, dport=80), proto=6)])
        self.assertEqual([x['name'] for x in r['http_hosts']], ['discord.com', 'example.org'])
        self.assertEqual(len(r['indicators']), 1)

    def test_endpoint_exact_udp_bidirectional_only(self):
        frames = [eth(udp(dns(), dport=51820)),
                  eth(udp(b'ciphertext', sport=51820, dport=50000), src=REMOTE, dst=LOCAL),
                  eth(tcp(record(hello()), dport=51820), proto=6),
                  eth(udp(dns(), dport=53))]
        r = self.run_capture(frames)
        self.assertEqual(r['wireguard_packets'], 2)
        self.assertEqual(len(r['indicators']), 2)

    def test_endpoint_udp_443_excluded_from_quic(self):
        meta = {'local_ips': [LOCAL], 'wireguard_endpoint': {'ip': REMOTE, 'port': 443}}
        r = self.run_capture([eth(udp(b'ciphertext', dport=443))], meta)
        self.assertEqual(r['wireguard_packets'], 1)
        self.assertEqual(r['quic_flows'], [])

    def test_quic_candidate_unparsed_and_benign_result(self):
        r = self.run_capture([eth(udp(b'not-decrypted', dport=443)), eth(udp(dns('example.org')))])
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['quic_flows'][0]['sni'], 'unparsed')
        self.assertEqual(r['quic_flows'][0]['dst'], REMOTE)

    def test_ipv6_noise_and_global_tcp_sni(self):
        frames = [eth(b'\x87' + b'\0' * 23, proto=58, src='fe80::1', dst='ff02::1:ff00:2', ipv6=True),
                  eth(tcp(record(hello())), proto=6, src='2001:db8::1', dst='2001:db8::2', ipv6=True),
                  eth(udp(dns()), src='fe80::1', dst='ff02::fb', ipv6=True)]
        r = self.run_capture(frames, {'local_ips': ['2001:db8::1', 'fe80::1']})
        self.assertEqual(r['ipv6_noise_packets'], 1)
        self.assertEqual(r['ipv6_packets'], 2)
        self.assertEqual(r['exit_code'], 2)
        self.assertNotIn('2001:db8::1', json.dumps(r))

    def test_ipv6_extension_header(self):
        data = bytes([6, 0]) + b'\0' * 6 + tcp(record(hello()))
        r = self.run_capture([eth(data, proto=0, src='2001:db8::1', dst='2001:db8::2', ipv6=True)])
        self.assertEqual(r['exit_code'], 2)

    def test_fragment_not_misparsed(self):
        r = self.run_capture([eth(udp(dns()), fragment=True)])
        self.assertEqual(r['fragmented_packets'], 1)
        self.assertEqual(r['exit_code'], 0)

    def test_truncated_snaplen_not_container_error(self):
        frame = eth(tcp(record(hello())), proto=6)
        r = self.run_capture([(frame[:70], len(frame))], fmt=pcap)
        self.assertEqual(r['truncated_packets'], 1)
        self.assertEqual(r['tls_sni'], [])

    def test_snaplen_sni_early_in_long_hello(self):
        data = record(hello() + b'\0' * 400)
        # The TLS record is truncated, but the SNI itself is complete.
        frame = eth(tcp(data), proto=6)
        r = self.run_capture([(frame[:256], len(frame))], fmt=pcap)
        self.assertEqual(r['exit_code'], 2)

    def test_missing_inventory_masks_all_ips(self):
        r = self.run_capture([eth(udp(b'x', dport=443))], {})
        self.assertNotIn(LOCAL, json.dumps(r))
        self.assertNotIn(REMOTE, json.dumps(r))

    def test_local_ip_in_host_name_masked(self):
        data = ('GET / HTTP/1.1\r\nHost: ' + LOCAL + '\r\n\r\n').encode()
        r = self.run_capture([eth(tcp(data, dport=80), proto=6)])
        self.assertEqual(r['http_hosts'][0]['name'], '<local>')
        self.assertNotIn(LOCAL, json.dumps(r))

    def test_empty_and_incomplete_capture_warnings(self):
        r = self.run_capture([], dict(META, capture_complete=False))
        self.assertTrue(any('Empty capture' in w for w in r['warnings']))
        self.assertTrue(any('incomplete' in w for w in r['warnings']))

    def test_dns_query_with_source_port_53(self):
        r = self.run_capture([eth(udp(dns(), sport=53, dport=53000))])
        self.assertEqual(r['exit_code'], 2)

    def test_broken_container_and_unsupported_link(self):
        samples = [b'', b'junk', pcapng([])[:-1], pcap([]) + b'\0',
                   pcapng([eth(udp(dns()))], link=101)]
        bad = bytearray(pcapng([]))
        bad[24] ^= 1
        samples.append(bytes(bad))
        for sample in samples:
            self.path.write_bytes(sample)
            with self.assertRaises(a.ParseError):
                a.analyze(self.path, META)

    def test_cli_exit_codes_json_and_privacy(self):
        for frame, code in [(eth(udp(dns())), 2), (eth(udp(dns('example.org'))), 0)]:
            self.path.write_bytes(pcapng([frame]))
            self.path.with_suffix('.json').write_text(json.dumps(META), encoding='utf-8-sig')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = a.main([str(self.path)])
            self.assertEqual(result, code)
            report = self.path.with_suffix('.report.json').read_text()
            self.assertNotIn(LOCAL, report + out.getvalue())
            self.assertEqual(json.loads(report)['exit_code'], code)
        self.path.write_bytes(b'not a capture')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(a.main([str(self.path)]), 1)

    def test_report_cannot_overwrite_input(self):
        self.path.write_bytes(pcapng([]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(a.main([str(self.path), '--json', str(self.path)]), 1)
        self.assertTrue(self.path.read_bytes().startswith(b'\x0a\x0d\x0d\x0a'))


if __name__ == '__main__':
    unittest.main()
