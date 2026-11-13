package dnsrewrite

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	workID     = "profile-work"
	personalID = "profile-personal"
)

var (
	ishiroCanonical = netip.MustParseAddr("100.64.0.3")
	ishiroEffective = netip.MustParseAddr("100.127.0.25")
	publicEdge      = netip.MustParseAddr("104.16.0.1")
)

func testProfiles() []Profile {
	return []Profile{
		{ID: workID, Peers: []Peer{{
			DNSName:   "ishiro.work.example.",
			Addresses: []AddressPair{{Canonical: ishiroCanonical, Effective: ishiroEffective}},
		}}},
		{ID: personalID, Peers: []Peer{{
			DNSName:   "nas.personal.example.",
			Addresses: []AddressPair{{Canonical: netip.MustParseAddr("100.64.0.9"), Effective: netip.MustParseAddr("100.127.0.40")}},
		}}},
	}
}

// newTestResolver returns a resolver whose upstream replies with reply and
// routes shekel.example to the work profile.
func newTestResolver(t *testing.T, reply func([]byte) ([]byte, error)) (*resolver, *fakeUpstream) {
	t.Helper()
	up := &fakeUpstream{reply: reply}
	r := &resolver{fwd: newTestForwarder(nil, up), maxAnswerTTL: DefaultMaxAnswerTTL}
	setTable(r, []Route{{Suffix: "shekel.example", ProfileID: workID}}, testProfiles())
	return r, up
}

// testCtx bounds a query so a broken upstream path fails instead of hanging.
func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func setTable(r *resolver, routes []Route, profiles []Profile) {
	e := &Engine{res: r}
	e.Update(routes, profiles)
}

// answerWith replies with the given answer records and header flags.
func answerWith(t *testing.T, rcode dnsmessage.RCode, ad bool, answers func(q dnsmessage.Question) []dnsmessage.Resource) func([]byte) ([]byte, error) {
	return func(query []byte) ([]byte, error) {
		var q dnsmessage.Message
		must(t, q.Unpack(query))
		m := dnsmessage.Message{
			Header:      dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RCode: rcode, AuthenticData: ad},
			Questions:   q.Questions,
			Answers:     answers(q.Questions[0]),
			Additionals: q.Additionals,
		}
		return m.Pack()
	}
}

func aRecord(name string, ttl uint32, addr netip.Addr) dnsmessage.Resource {
	return addrResource(dnsmessage.MustNewName(name), addr, ttl)
}

func cname(name, target string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func rrsigOver(name string, covered dnsmessage.Type) dnsmessage.Resource {
	data := make([]byte, 18)
	binary.BigEndian.PutUint16(data, uint16(covered))
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typeRRSIG, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.UnknownResource{Type: typeRRSIG, Data: data},
	}
}

func addrs(t *testing.T, m dnsmessage.Message) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, rr := range m.Answers {
		if a, ok := addrOf(rr); ok {
			out = append(out, a)
		}
	}
	return out
}

func TestRewritesCanonicalPeerAddressToEffective(t *testing.T) {
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeSuccess, true, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical), rrsigOver(q.Name.String(), dnsmessage.TypeA)}
	}))
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{id: 7, name: "ishiro.shekel.example."}), true))
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroEffective {
		t.Fatalf("answers = %v, want [%v]", got, ishiroEffective)
	}
	if m.Answers[0].Header.TTL != DefaultMaxAnswerTTL {
		t.Errorf("TTL = %d, want %d", m.Answers[0].Header.TTL, DefaultMaxAnswerTTL)
	}
	if m.AuthenticData {
		t.Error("AD bit kept on a rewritten answer")
	}
	for _, rr := range m.Answers {
		if rr.Header.Type == typeRRSIG {
			t.Error("RRSIG over a rewritten RRset was kept")
		}
	}
	if m.ID != 7 {
		t.Errorf("ID = %d, want 7", m.ID)
	}
}

func TestPublicAddressPassesThroughUnchanged(t *testing.T) {
	var upstreamBytes []byte
	reply := answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, publicEdge)}
	})
	r, _ := newTestResolver(t, func(q []byte) ([]byte, error) {
		b, err := reply(q)
		upstreamBytes = b
		return b, err
	})
	got := r.handle(testCtx(t), buildQuery(t, queryOpts{name: "www.shekel.example."}), true)
	if string(got) != string(upstreamBytes) {
		t.Fatal("public answer was modified")
	}
}

func TestCNAMEToPeerIsCompletedFromPeerMap(t *testing.T) {
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeNameError, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{cname(q.Name.String(), "ishiro.work.example.", 300)}
	}))
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "app.shekel.example."}), true))
	if m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", m.RCode)
	}
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroEffective {
		t.Fatalf("answers = %v, want [%v]", got, ishiroEffective)
	}
}

func TestAddressOwnedByAnotherProfileIsNotRewritten(t *testing.T) {
	other := netip.MustParseAddr("100.64.0.9") // personal profile's peer
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical), aRecord(q.Name.String(), 300, other)}
	}))
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "mixed.shekel.example."}), true))
	got := addrs(t, m)
	if len(got) != 2 || got[0] != ishiroCanonical || got[1] != other {
		t.Fatalf("ambiguous answer was rewritten: %v", got)
	}
}

func TestPeerNameIsSynthesizedWithoutUpstream(t *testing.T) {
	up := &fakeUpstream{reply: func([]byte) ([]byte, error) { return nil, errors.New("upstream must not be queried") }}
	r := &resolver{fwd: newTestForwarder(nil, up), maxAnswerTTL: DefaultMaxAnswerTTL}
	setTable(r, []Route{{Suffix: "work.example", ProfileID: workID}}, testProfiles())
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "ishiro.work.example."}), true))
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroEffective {
		t.Fatalf("answers = %v, want [%v]", got, ishiroEffective)
	}
	if calls := up.calls.Load(); calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}
	// The peer has no IPv6 address: NOERROR with no answers, not NXDOMAIN.
	m = unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "ishiro.work.example.", qtype: dnsmessage.TypeAAAA}), true))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("AAAA = %v with %d answers, want NOERROR/NODATA", m.RCode, len(m.Answers))
	}
}

func TestRouteToStoppedProfileCapsTTL(t *testing.T) {
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical)}
	}))
	setTable(r, []Route{{Suffix: "shekel.example", ProfileID: workID}}, nil)
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "ishiro.shekel.example."}), true))
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroCanonical {
		t.Fatalf("answers = %v, want untranslated %v", got, ishiroCanonical)
	}
	if m.Answers[0].Header.TTL != DefaultMaxAnswerTTL {
		t.Errorf("TTL = %d, want capped %d", m.Answers[0].Header.TTL, DefaultMaxAnswerTTL)
	}
}

func TestUnroutedNameKeepsUpstreamAnswer(t *testing.T) {
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical)}
	}))
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "ishiro.elsewhere.example."}), true))
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroCanonical || m.Answers[0].Header.TTL != 300 {
		t.Fatalf("unrouted answer changed: %v ttl %d", got, m.Answers[0].Header.TTL)
	}
}

func TestLongestRouteSuffixWins(t *testing.T) {
	r, _ := newTestResolver(t, answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical)}
	}))
	setTable(r, []Route{
		{Suffix: "shekel.example", ProfileID: workID},
		{Suffix: "lab.shekel.example", ProfileID: personalID},
	}, testProfiles())
	// Under lab.shekel.example the personal profile is selected, and the
	// work-owned address is ambiguous for it, so nothing is rewritten.
	m := unpack(t, r.handle(testCtx(t), buildQuery(t, queryOpts{name: "x.lab.shekel.example."}), true))
	if got := addrs(t, m); len(got) != 1 || got[0] != ishiroCanonical {
		t.Fatalf("answers = %v, want untranslated", got)
	}
}

func TestEngineServesUDPAndTCPAndKeepsCacheAcrossUpdate(t *testing.T) {
	e, err := Start(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	up := &fakeUpstream{reply: answerWith(t, dnsmessage.RCodeSuccess, false, func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{aRecord(q.Name.String(), 300, ishiroCanonical)}
	})}
	e.res.fwd = newTestForwarder(nil, up)
	e.Update([]Route{{Suffix: "shekel.example", ProfileID: workID}}, testProfiles())

	query := buildQuery(t, queryOpts{id: 42, name: "ishiro.shekel.example."})
	for _, network := range []string{"udp", "tcp"} {
		m := unpack(t, exchange(t, network, e.Addr(), query))
		if got := addrs(t, m); len(got) != 1 || got[0] != ishiroEffective || m.ID != 42 {
			t.Fatalf("%s: answers = %v id %d", network, got, m.ID)
		}
	}
	// New peer data takes effect without another upstream query.
	moved := netip.MustParseAddr("100.127.0.99")
	e.Update([]Route{{Suffix: "shekel.example", ProfileID: workID}}, []Profile{{ID: workID, Peers: []Peer{{
		DNSName:   "ishiro.work.example",
		Addresses: []AddressPair{{Canonical: ishiroCanonical, Effective: moved}},
	}}}})
	m := unpack(t, exchange(t, "udp", e.Addr(), query))
	if got := addrs(t, m); len(got) != 1 || got[0] != moved {
		t.Fatalf("after update: answers = %v, want [%v]", got, moved)
	}
	if calls := up.calls.Load(); calls != 1 {
		t.Errorf("upstream calls = %d, want 1 (cache kept across Update)", calls)
	}
}

func exchange(t *testing.T, network string, addr netip.AddrPort, query []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout(network, addr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	must(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	if network == "tcp" {
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		copy(framed[2:], query)
		if _, err := conn.Write(framed); err != nil {
			t.Fatal(err)
		}
		var lenBuf [2]byte
		if _, err := conn.Read(lenBuf[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		n := 0
		for n < len(resp) {
			k, err := conn.Read(resp[n:])
			if err != nil {
				t.Fatal(err)
			}
			n += k
		}
		return resp
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxDNSMessage)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}
