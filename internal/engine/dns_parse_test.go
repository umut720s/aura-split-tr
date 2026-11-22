package engine

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsRR struct {
	owner string
	class dnsmessage.Class
	a     *[4]byte
	cname string
}

type dnsCase struct {
	hdr       dnsmessage.Header
	questions []dnsmessage.Question
	answers   []dnsRR
}

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func buildDNS(t *testing.T, c dnsCase) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, c.hdr)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range c.questions {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, rr := range c.answers {
		h := dnsmessage.ResourceHeader{Name: mustName(t, rr.owner), Class: rr.class, TTL: 60}
		var err error
		if rr.a != nil {
			err = b.AResource(h, dnsmessage.AResource{A: *rr.a})
		} else {
			err = b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: mustName(t, rr.cname)})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseDNSResponseValidation(t *testing.T) {
	const id = 0x1234
	const fqdn = "www.example.com."
	ip1, ip2 := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	in := dnsmessage.ClassINET
	q := dnsmessage.Question{Name: mustName(t, fqdn), Type: dnsmessage.TypeA, Class: in}
	ok := dnsmessage.Header{ID: id, Response: true}
	cases := []struct {
		name string
		c    dnsCase
		ours bool
		err  bool
		want []netip.Addr
	}{
		{"plain answer", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{{fqdn, in, &ip1, ""}}}, true, false,
			[]netip.Addr{netip.AddrFrom4(ip1)}},
		{"case-insensitive owner", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{{"WWW.Example.COM.", in, &ip1, ""}}}, true, false,
			[]netip.Addr{netip.AddrFrom4(ip1)}},
		{"wrong id", dnsCase{dnsmessage.Header{ID: id + 1, Response: true}, []dnsmessage.Question{q}, []dnsRR{{fqdn, in, &ip1, ""}}}, false, false, nil},
		{"not a response", dnsCase{dnsmessage.Header{ID: id}, []dnsmessage.Question{q}, nil}, false, false, nil},
		{"opcode not query", dnsCase{dnsmessage.Header{ID: id, Response: true, OpCode: 2}, []dnsmessage.Question{q}, []dnsRR{{fqdn, in, &ip1, ""}}}, false, false, nil},
		{"no question", dnsCase{ok, nil, []dnsRR{{fqdn, in, &ip1, ""}}}, false, false, nil},
		{"two questions", dnsCase{ok, []dnsmessage.Question{q, q}, []dnsRR{{fqdn, in, &ip1, ""}}}, false, false, nil},
		{"question other name", dnsCase{ok, []dnsmessage.Question{{Name: mustName(t, "evil.example."), Type: dnsmessage.TypeA, Class: in}}, nil}, false, false, nil},
		{"question other type", dnsCase{ok, []dnsmessage.Question{{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: in}}, nil}, false, false, nil},
		{"question other class", dnsCase{ok, []dnsmessage.Question{{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassCHAOS}}, nil}, false, false, nil},
		{"rcode", dnsCase{dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeServerFailure}, []dnsmessage.Question{q}, nil}, true, true, nil},
		{"truncated", dnsCase{dnsmessage.Header{ID: id, Response: true, Truncated: true}, []dnsmessage.Question{q}, nil}, true, true, nil},
		{"unrelated owner ignored", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{{"evil.example.", in, &ip2, ""}, {fqdn, in, &ip1, ""}}}, true, false,
			[]netip.Addr{netip.AddrFrom4(ip1)}},
		{"non-IN class ignored", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{{fqdn, dnsmessage.ClassCHAOS, &ip2, ""}}}, true, false, nil},
		{"cname chain", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{
			{fqdn, in, nil, "a.cdn.example."}, {"a.cdn.example.", in, nil, "b.cdn.example."}, {"b.cdn.example.", in, &ip1, ""},
		}}, true, false, []netip.Addr{netip.AddrFrom4(ip1)}},
		{"cname not from the question", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{
			{"other.example.", in, nil, "b.cdn.example."}, {"b.cdn.example.", in, &ip1, ""},
		}}, true, false, nil},
		{"non-IN cname not followed", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{
			{fqdn, dnsmessage.ClassCHAOS, nil, "b.cdn.example."}, {"b.cdn.example.", in, &ip1, ""},
		}}, true, false, nil},
		{"cname loop terminates", dnsCase{ok, []dnsmessage.Question{q}, []dnsRR{
			{fqdn, in, nil, "x.example."}, {"x.example.", in, nil, fqdn},
		}}, true, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ours, err := parseDNSResponse(buildDNS(t, tc.c), id, fqdn, dnsmessage.TypeA)
			if ours != tc.ours || (err != nil) != tc.err {
				t.Fatalf("ours=%v err=%v", ours, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("addrs %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("addrs %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A CNAME chain longer than maxCNAMEChain is not followed to its end.
func TestParseDNSResponseCNAMEBound(t *testing.T) {
	const fqdn = "www.example.com."
	ip := [4]byte{192, 0, 2, 9}
	in := dnsmessage.ClassINET
	var rrs []dnsRR
	owner := fqdn
	for i := 0; i <= maxCNAMEChain; i++ {
		next := string(rune('a'+i)) + ".chain.example."
		rrs = append(rrs, dnsRR{owner, in, nil, next})
		owner = next
	}
	rrs = append(rrs, dnsRR{owner, in, &ip, ""})
	c := dnsCase{dnsmessage.Header{ID: 7, Response: true},
		[]dnsmessage.Question{{Name: mustName(t, fqdn), Type: dnsmessage.TypeA, Class: in}}, rrs}
	got, ours, err := parseDNSResponse(buildDNS(t, c), 7, fqdn, dnsmessage.TypeA)
	if !ours || err != nil || len(got) != 0 {
		t.Fatalf("addrs %v ours %v err %v", got, ours, err)
	}
}
