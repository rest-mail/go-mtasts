package mtasts

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// dnsName encodes a domain name as DNS labels.
func dnsName(name string) []byte {
	var b []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// dnsRR encodes a resource record of class IN with a TTL of 300.
func dnsRR(name []byte, typ uint16, rdata []byte) []byte {
	b := append([]byte{}, name...)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 300)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// fakeDNS returns a Dial function for a net.Resolver that answers every query
// itself, over a stream connection, with the CNAME chain and TXT strings
// given: _mta-sts.example.com CNAME each name of chain in turn, the last of
// which holds one TXT record made of strs.
func fakeDNS(t *testing.T, chain []string, strs []string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			var n uint16
			if err := binary.Read(server, binary.BigEndian, &n); err != nil {
				return
			}
			q := make([]byte, n)
			if _, err := io.ReadFull(server, q); err != nil {
				return
			}
			// The question runs from the header to the end of its name, plus
			// its type and class.
			end := 12
			for q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			resp := append([]byte{}, q[:2]...)
			resp = append(resp, 0x81, 0x80, 0, 1)
			resp = binary.BigEndian.AppendUint16(resp, uint16(len(chain)+1))
			resp = append(resp, 0, 0, 0, 0)
			resp = append(resp, q[12:end]...)
			owner := []byte{0xc0, 12}
			for _, target := range chain {
				resp = append(resp, dnsRR(owner, 5, dnsName(target))...)
				owner = dnsName(target)
			}
			var txt []byte
			for _, s := range strs {
				txt = append(txt, byte(len(s)))
				txt = append(txt, s...)
			}
			resp = append(resp, dnsRR(owner, 16, txt)...)
			out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
			if _, err := server.Write(append(out, resp...)); err != nil {
				t.Errorf("fake DNS: %v", err)
			}
		}()
		return client, nil
	}
}

// TestDefaultResolverTXT checks the default TXT lookup, a net.Resolver's:
// a record of several strings is read as the strings joined without spaces,
// and a CNAME chain at _mta-sts is followed to the record.
//
// checklist: MTASTS-TXT-05 MTASTS-TXT-06
func TestDefaultResolverTXT(t *testing.T) {
	cases := []struct {
		name  string
		chain []string
	}{
		{"direct", nil},
		{"CNAME", []string{"_mta-sts.policy.example.net"}},
		{"CNAME chain", []string{"a.example.net", "b.example.org"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dns := &net.Resolver{PreferGo: true, Dial: fakeDNS(t, c.chain, []string{"v=STSv1;", " id=2024", "0101Z"})}
			f := newFakeResolver()
			f.LookupTXT = dns.LookupTXT
			f.policies[PolicyURL("example.com")] = testPolicyBody
			p, err := f.Resolve(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if p.Mode != ModeEnforce {
				t.Errorf("Resolve = %+v", p)
			}
			txts, err := dns.LookupTXT(context.Background(), TXTName("example.com"))
			if err != nil || len(txts) != 1 || txts[0] != "v=STSv1; id=20240101Z" {
				t.Fatalf("LookupTXT = (%q, %v), want the one record joined", txts, err)
			}
			if id, ok := parseTXTID(txts); !ok || id != "20240101Z" {
				t.Errorf("parseTXTID = (%q, %v)", id, ok)
			}
		})
	}
}
