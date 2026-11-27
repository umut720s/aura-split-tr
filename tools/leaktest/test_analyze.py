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


def pcapng(frames, e='<', packet_type=6, link=1, timestamp=0):
    b = block(0x0a0d0d0a, struct.pack(e + 'IHHq', 0x1a2b3c4d, 1, 0, -1), e)
    b += block(1, struct.pack(e + 'HHI', link, 0, 65535), e)
    for frame in frames:
        if packet_type == 3:
            body = struct.pack(e + 'I', len(frame))
        elif packet_type == 2:
            body = struct.pack(e + 'HHIIII', 0, 0, 0, timestamp, len(frame), len(frame))
        else:
            body = struct.pack(e + 'IIIII', 0, 0, timestamp, len(frame), len(frame))
        b += block(packet_type, body + frame, e)
    return b


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        # Synthetic artifacts stay in the system temporary directory.
        self.tmp = tempfile.TemporaryDirectory()
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
                self.assertEqual(r['exit_code'], 0)
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
        self.assertEqual(r['exit_code'], 0)
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
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(len(r['dns_queries']), 1)

    def test_tls_sni_any_port_split_record_and_tcp(self):
        h = hello()
        data = record(h[:25]) + record(h[25:])
        r = self.run_capture([eth(tcp(data[:31], dport=8443), proto=6),
                              eth(tcp(data[31:], dport=8443, seq=131), proto=6)])
        self.assertEqual(r['tls_sni'][0]['name'], 'gateway.discord.gg')
        self.assertEqual(r['exit_code'], 0)

    def test_tls_sequence_wraparound(self):
        data = record(hello())
        r = self.run_capture([eth(tcp(data[:20], seq=0xfffffff0), proto=6),
                              eth(tcp(data[20:], seq=4), proto=6)])
        self.assertEqual(r['exit_code'], 0)

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
        self.assertEqual(r['exit_code'], 0)
        self.assertNotIn('2001:db8::1', json.dumps(r))

    def test_ipv6_extension_header(self):
        data = bytes([6, 0]) + b'\0' * 6 + tcp(record(hello()))
        r = self.run_capture([eth(data, proto=0, src='2001:db8::1', dst='2001:db8::2', ipv6=True)])
        self.assertEqual(r['exit_code'], 0)

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
        self.assertEqual(r['exit_code'], 0)

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
        self.assertEqual(r['exit_code'], 0)

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

    def test_report_cannot_overwrite_input(self):
        self.path.write_bytes(pcapng([]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(a.main([str(self.path), '--json', str(self.path)]), 1)
        self.assertTrue(self.path.read_bytes().startswith(b'\x0a\x0d\x0d\x0a'))






class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / 'run.json'
        self.tun = '172.19.0.1'
        self.peer = '203.0.113.8'
        self.p = dict(pid=101, exe=r'C:\Test\control.exe', started=900)
        self.controls = [dict(mode=mode, nonce='AURA-P0B-' + mode, pid=101, process_started=900,
                              local_ip=ip, local_port=50000, remote_ip=remote, remote_port=9000,
                              started=999, ended=1002)
                         for mode, ip, remote in [('direct', LOCAL, REMOTE), ('tunnel', self.tun, '198.51.100.20')]]
        sockets = [dict(proto=17, pid=101, local_ip=c['local_ip'], local_port=50000) for c in self.controls]
        sockets.append(dict(proto=17, pid=303, local_ip=LOCAL, local_port=50001))
        engine = dict(pid=303, exe=r'C:\Test\aurasplit.exe', started=800)
        self.snapshots = [dict(time=t, active_physical=[1], processes=[self.p, engine], sockets=sockets,
                               peer=dict(ip=self.peer, port=51820)) for t in (999, 1001)]
        self.meta = dict(activation=dict(time=999, source='capture_operator_confirmation', policy_applied=True, tunnel_up=True), executable_manifest=a.EXECUTABLE_MANIFEST, scenario='L1', started=998, ended=1003, capture_complete=True, max_snapshot_gap=5,
                         interfaces=[dict(if_index=i, component_id=i, kind=kind, local_ips=[ip],
                                          pcapng=[kind + '.pcapng'], drops_pcapng=[kind + '-drops.pcapng'])
                                     for i, kind, ip in [(1, 'physical', LOCAL), (2, 'tun', self.tun)]])
        self.review = {k: True for k in ('loss_checked', 'coverage_checked', 'scenario_stimulus_observed',
                                         'encrypted_metadata_checked', 'outer_correlation_checked')}
        self.review.update(capture_loss=False, tunnel_receipts={'AURA-P0B-tunnel': dict(received_via_tunnel=True, evidence='receiver log: nonce via VPN exit')})
        direct = eth(udp(self.controls[0]['nonce'].encode(), dport=9000))
        outer = eth(udp(b'\x04\0\0\0' + b'X' * 64, sport=50001, dport=51820), dst=self.peer)
        tunnel = eth(udp(self.controls[1]['nonce'].encode(), dport=9000), src=self.tun, dst='198.51.100.20')
        self.frames = {'physical': [direct, outer], 'tun': [tunnel]}
        for kind in self.frames:
            (self.root / (kind + '-drops.pcapng')).write_bytes(pcapng([]))

    def run_fixture(self):
        self.manifest.write_text(json.dumps(self.meta))
        for name, records in [('snapshots', self.snapshots), ('controls', self.controls)]:
            (self.root / (name + '.jsonl')).write_text('\n'.join(json.dumps(r) for r in records))
        for kind, frames in self.frames.items():
            (self.root / (kind + '.pcapng')).write_bytes(pcapng(frames, timestamp=1000000000))
        return a.analyze_run(self.manifest, self.review)

    def assert_inconclusive(self, issue):
        result = self.run_fixture()
        self.assertEqual(result['result'], 'INCONCLUSIVE', result)
        self.assertIn(issue, result['issues'])
        return result

    def test_complete_scoped_pass_requires_positive_controls(self):
        result = self.run_fixture()
        self.assertEqual(result['result'], 'PASS', result)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual([f['kind'] for f in result['flows']], ['physical', 'physical', 'tun'])
        self.assertEqual(result['flows'][0]['process']['pid'], 101)
        self.assertEqual(result['flows'][0]['time'], 1000)
        self.assertEqual(result['flows'][0]['direction'], 'out')

    def test_activation_boundary_preserves_baseline_and_catches_later_leak(self):
        process = dict(pid=202, exe=r'C:\AppData\Local\Discord\app-1\Discord.exe', started=950)
        self.snapshots[0]['processes'].append(process)
        self.snapshots[0]['sockets'].append(dict(proto=17, pid=202, local_ip=LOCAL, local_port=60000))
        self.run_fixture()
        frame = eth(udp(b'opaque baseline', sport=60000, dport=12345))
        path = self.root / 'physical.pcapng'
        normal = path.read_bytes()
        path.write_bytes(pcapng([frame], timestamp=998500000) + normal)
        result = a.analyze_run(self.manifest, self.review)
        self.assertEqual(result['result'], 'PASS', result)
        self.assertEqual(len(result['baseline']), 1)
        self.assertEqual(result['flows'][result['baseline'][0]]['process']['pid'], 202)
        self.assertFalse(result['leaks'])
        # The exact boundary belongs to the protected window.
        path.write_bytes(path.read_bytes() + pcapng([frame], timestamp=999000000))
        result = a.analyze_run(self.manifest, self.review)
        self.assertEqual(result['result'], 'FAIL', result)
        self.assertEqual(len(result['leaks']), 1)
        self.assertTrue(set(result['baseline']).isdisjoint(result['leaks']))

    def test_activation_requires_capture_confirmation_and_valid_window(self):
        valid = dict(self.meta['activation'])
        for marker in ({}, dict(valid, time=997), dict(valid, time=1004),
                       dict(valid, time=float('nan')), dict(valid, policy_applied=False),
                       dict(valid, tunnel_up=False), dict(valid, source='unverified')):
            self.meta['activation'] = marker
            self.assert_inconclusive('verified_activation_boundary_missing')

    def test_engine_inventory_parity_and_exact_host_boundary(self):
        suffixes, hosts = a.domain_inventory()
        self.assertEqual(a.DOMAINS, suffixes)
        self.assertEqual(a.HOSTS, hosts)
        self.assertIn('discord-attachments-uploads-prd.storage.googleapis.com', hosts)
        for host in hosts:
            self.assertTrue(a.discord(host.upper() + '.'))
            self.assertFalse(a.discord('child.' + host))
        for host in ('googleapis.com', 'storage.googleapis.com', 'other.storage.googleapis.com'):
            self.assertFalse(a.discord(host))
        # Contract parser must reflect a changed engine list, not silently retain a copied list.
        source = self.root / 'config.go'
        source.write_text('var DiscordDomains = []string{"test.example"}\nvar DiscordHosts = []string{"exact.example"}')
        self.assertEqual(a.domain_inventory(source), (('test.example',), ('exact.example',)))

    def test_executable_manifest_parity(self):
        for root in a.EXECUTABLE_MANIFEST['roots']:
            base = 'C:/Users/fixture/AppData/Local/' + root + '/'
            for tail in ('Update.exe', 'app-1/Discord.exe', 'app-1/audio_effects_helper.exe', 'DiscordPTBSetup.exe'):
                self.assertTrue(a.protected(base + tail))
            self.assertFalse(a.protected(base + 'utility.exe'))
        self.assertFalse(a.protected('C:/Users/fixture/AppData/Local/DiscordCustom/app-1/audio_effects_helper.exe'))
        self.assertFalse(a.protected('C:/Users/fixture/Downloads/DiscordSetup.exe'))
        changed = dict(a.EXECUTABLE_MANIFEST, path_regex=r'(?i)\\only\\exact.exe$')
        self.assertTrue(a.protected('C:/only/exact.exe', changed))
        self.assertFalse(a.protected('C:/Users/fixture/AppData/Local/Discord/Update.exe', changed))

    def test_missing_executable_manifest(self):
        del self.meta['executable_manifest']
        self.assert_inconclusive('executable_manifest_missing_or_mismatched')

    def test_tun_never_appeared(self):
        self.meta['interfaces'] = self.meta['interfaces'][:1]
        self.assert_inconclusive('missing_physical_or_tun')

    def test_empty(self):
        self.frames['physical'] = []
        self.assert_inconclusive('empty_interface_capture')

    def test_fragments(self):
        self.frames['physical'].append(eth(udp(b'fragment'), fragment=True))
        self.assert_inconclusive('fragments')

    def test_truncation(self):
        self.run_fixture()
        frame = eth(udp(b'X' * 100))
        (self.root / 'physical.pcapng').write_bytes(pcap([(frame[:60], len(frame))]))
        result = a.analyze_run(self.manifest, self.review)
        self.assertEqual(result['result'], 'INCONCLUSIVE')
        self.assertIn('truncation', result['issues'])

    def test_drop_capture(self):
        (self.root / 'physical-drops.pcapng').write_bytes(pcapng([eth(udp(b'dropped'))]))
        self.assert_inconclusive('packet_drops')

    def test_pcapng_drop_statistics_and_epb_dropcount(self):
        self.run_fixture()
        for suffix in [block(5, struct.pack('<IIIHHQHH', 0, 0, 0, 5, 8, 1, 0, 0)),
                       block(6, struct.pack('<IIIII', 0, 0, 0, 0, 0) + struct.pack('<HHQHH', 4, 8, 1, 0, 0))]:
            path = self.root / 'physical.pcapng'
            path.write_bytes(pcapng(self.frames['physical'], timestamp=1000000000) + suffix)
            result = a.analyze_run(self.manifest, self.review)
            self.assertEqual(result['result'], 'INCONCLUSIVE')
            self.assertIn('capture_parse_error_or_drops', result['issues'])

    def test_missing_interface(self):
        self.snapshots[1]['active_physical'].append(3)
        self.assert_inconclusive('physical_interface_not_captured')

    def test_missing_tun_capture(self):
        self.meta['interfaces'][1]['pcapng'] = []
        self.assert_inconclusive('interface_capture_missing')

    def test_unattributed_related_destination(self):
        self.frames['physical'].append(eth(udp(dns(), sport=60000)))
        self.assert_inconclusive('unattributed_physical_flow')

    def test_known_related_destination_fail(self):
        self.frames['physical'].append(eth(udp(dns(), dport=53)))
        result = self.run_fixture()
        self.assertEqual(result['result'], 'FAIL', result)
        self.assertTrue(result['leaks'])
        self.assertEqual(result['exit_code'], 0)

    def test_exact_upload_host_fail(self):
        self.frames['physical'].append(eth(udp(dns(a.HOSTS[0]))))
        self.assertEqual(self.run_fixture()['result'], 'FAIL')

    def test_protected_process_ip_only_fail(self):
        self.snapshots[0]['processes'].append(dict(pid=202, exe=r'C:\AppData\Local\Discord\app-1\audio_effects_helper.exe', started=950))
        self.snapshots[0]['sockets'].append(dict(proto=17, pid=202, local_ip=LOCAL, local_port=60000))
        self.frames['physical'].append(eth(udp(b'opaque', sport=60000, dport=12345)))
        self.assertEqual(self.run_fixture()['result'], 'FAIL')

    def test_no_domains_is_not_pass(self):
        self.review = {}
        self.assert_inconclusive('scenario_stimulus_observed_not_reviewed')

    def test_missing_direct_control(self):
        self.frames['physical'] = self.frames['physical'][1:]
        self.assert_inconclusive('direct_positive_control_missing')

    def test_missing_tunnel_control(self):
        self.frames['tun'] = []
        self.assert_inconclusive('tunnel_positive_control_missing')

    def test_handshake_not_data_control(self):
        self.frames['physical'][1] = eth(udp(b'\x01\0\0\0' + b'X' * 64, dport=51820), dst=self.peer)
        self.assert_inconclusive('tunnel_positive_control_missing')

    def test_peer_endpoint_change(self):
        self.snapshots[0]['peer']['ip'] = '203.0.113.99'
        self.assert_inconclusive('tunnel_positive_control_missing')

    def test_outer_udp_alone_not_proof(self):
        self.review['tunnel_receipts'] = {}
        self.assert_inconclusive('tunnel_positive_control_missing')

    def test_tunnel_nonce_on_physical(self):
        self.frames['physical'].append(eth(udp(self.controls[1]['nonce'].encode(), dport=9000), src=self.tun, dst='198.51.100.20'))
        self.meta['interfaces'][0]['local_ips'].append(self.tun)
        result = self.assert_inconclusive('tunnel_positive_control_missing')
        self.assertTrue(result['leaks'])

    def test_pid_reuse_or_shared_udp_port_is_unknown(self):
        self.snapshots[0]['processes'].append(dict(pid=102, exe='other.exe', started=910))
        self.snapshots[0]['sockets'].append(dict(proto=17, pid=102, local_ip='0.0.0.0', local_port=50000))
        self.assert_inconclusive('unattributed_physical_flow')

    def test_opaque_flow_requires_telemetry(self):
        self.frames['physical'].append(eth(udp(b'encrypted DNS or QUIC', dport=443)))
        self.assert_inconclusive('opaque_flow_requires_telemetry')

    def test_quality_gate_overrides_leak_result(self):
        self.frames['physical'].append(eth(udp(dns())))
        self.meta['capture_complete'] = False
        result = self.assert_inconclusive('incomplete_capture')
        self.assertTrue(result['leaks'])

    def test_snapshot_gap(self):
        self.snapshots[1]['time'] = 1010
        self.assert_inconclusive('snapshot_gap')

    def test_boot_resume_requires_external_analysis(self):
        for scenario in ('L9', 'L10'):
            self.meta['scenario'] = scenario
            self.assert_inconclusive('external_continuity_not_analyzed')

    def test_unknown_tun_process(self):
        self.frames['tun'].append(eth(udp(dns(), sport=60000), src=self.tun))
        self.assert_inconclusive('unattributed_tun_flow')

    def test_unknown_wireguard_owner(self):
        for snapshot in self.snapshots:
            snapshot['processes'] = [self.p]
        self.assert_inconclusive('unattributed_physical_flow')

    def test_tun_recreation_inventory_error(self):
        self.meta['inventory_errors'] = ['TUN identity changed']
        self.assert_inconclusive('inventory_errors')

    def test_reused_pid_new_start_not_prior_owner(self):
        self.snapshots[0]['processes'][0] = dict(pid=101, exe='other.exe', started=990)
        self.assert_inconclusive('unattributed_physical_flow')

    def test_missing_drop_evidence(self):
        self.meta['interfaces'][0]['drops_pcapng'] = []
        self.assert_inconclusive('drop_evidence_missing')

    def test_allowlist_export(self):
        result = self.run_fixture()
        result['flows'][0]['process']['exe'] = r'C:\Users\private-user\secret.exe'
        result['scenario'] = '192.0.2.1 private-user'
        data = json.dumps(a.redacted(result))
        for sensitive in ('private-user', '192.0.2.', '198.51.100.', '203.0.113.', 'secret.exe', 'AURA-P0B'):
            self.assertNotIn(sensitive, data)

    def test_cli_exit_zero_for_fail_and_redacted_stdout(self):
        self.frames['physical'].append(eth(udp(dns())))
        self.run_fixture()
        review = self.root / 'review.json'
        review.write_text(json.dumps(self.review))
        export = self.root / 'export.json'
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = a.main([str(self.manifest), '--review', str(review), '--export', str(export)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())['result'], 'FAIL')
        self.assertNotIn(LOCAL, out.getvalue() + export.read_text())

    def test_packet_metadata_options(self):
        frame = eth(udp(b'x'))
        padding = b'\0' * (-len(frame) % 4)
        opts = struct.pack('<HHIHH', 2, 4, 2, 0, 0)
        data = pcapng([]) + block(6, struct.pack('<IIIII', 0, 0, 1000000000, len(frame), len(frame)) + frame + padding + opts)
        path = self.root / 'flags.pcapng'
        path.write_bytes(data)
        record = list(a.packets(path, detailed=True))[0]
        self.assertEqual(record['direction'], 2)
        self.assertEqual(record['timestamp'], 1000)
        self.assertEqual(record['interface'], 0)

if __name__ == '__main__':
    unittest.main()
