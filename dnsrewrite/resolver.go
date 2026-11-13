package dnsrewrite

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxCNAMEChain   = 16
	maxEDNSUDPSize  = 1232
	minUDPSize      = 512
	ednsAdvertised  = 1232
	typeRRSIG       = dnsmessage.Type(46)
	maxSynthAnswers = 16
)

// table is the immutable routing and peer state one query is answered with.
// tailmixd swaps it atomically after every reconciliation, so a query never
// waits on the daemon.
type table struct {
	routes []route // longest suffix first
	snap   *peerSnapshot
}

// route selects the profile whose peers may rewrite answers under suffix.
type route struct {
	suffix    string
	profileID string
}

func (t *table) match(name string) (route, bool) {
	for _, r := range t.routes {
		if name == r.suffix || strings.HasSuffix(name, "."+r.suffix) {
			return r, true
		}
	}
	return route{}, false
}

type resolver struct {
	fwd          *forwarder
	maxAnswerTTL uint32
	table        atomic.Pointer[table]
}

// queryInfo is the parsed, policy-relevant part of a client query.
type queryInfo struct {
	header    dnsmessage.Header
	question  dnsmessage.Question
	single    bool // exactly one IN-class question with a standard opcode
	malformed bool
	edns      bool
	udpSize   int
}

// handle answers one wire-format query. UDP answers larger than the client's
// advertised size are truncated with TC set. It returns nil when the packet
// should be dropped.
func (r *resolver) handle(ctx context.Context, query []byte, tcp bool) []byte {
	qi, ok := parseQuery(query)
	if !ok {
		return nil
	}
	limit := maxDNSMessage
	if !tcp {
		limit = minUDPSize
		if qi.edns {
			limit = max(minUDPSize, min(qi.udpSize, maxEDNSUDPSize))
		}
	}
	if qi.malformed {
		return fitResponse(errorResponse(qi, dnsmessage.RCodeFormatError), qi, limit)
	}

	var (
		profile *profileView
		snap    *peerSnapshot
		name    string
		routed  bool
	)
	addressQuery := qi.single && (qi.question.Type == dnsmessage.TypeA || qi.question.Type == dnsmessage.TypeAAAA)
	if t := r.table.Load(); addressQuery && t != nil {
		var valid bool
		name, valid = normalizeDomain(qi.question.Name.String())
		if valid && name != "" {
			if rt, matched := t.match(name); matched {
				routed = true
				snap = t.snap
				profile = snap.profile(rt.profileID)
			}
		}
	}

	// A known online peer FQDN in the selected profile is answered locally.
	if profile != nil {
		if addrs, ok := profile.peer(name); ok {
			resp, err := synthesize(qi, addrs.family(qi.question.Type == dnsmessage.TypeAAAA), r.maxAnswerTTL)
			if err == nil {
				return fitResponse(resp, qi, limit)
			}
		}
	}

	resp, err := r.fwd.forward(ctx, query)
	if err != nil {
		return fitResponse(errorResponse(qi, dnsmessage.RCodeServerFailure), qi, limit)
	}
	if profile != nil {
		resp = rewrite(resp, qi, name, profile, snap, r.maxAnswerTTL)
	} else if routed {
		// The selected profile is not running, so the answer may hold a
		// canonical tailnet address the host cannot route; keep OS caches
		// from holding it long.
		resp = capTTL(resp, r.maxAnswerTTL)
	}
	return fitResponse(resp, qi, limit)
}

// capTTL lowers every record TTL in resp to at most maxTTL. The OPT pseudo-
// record is left alone because its TTL field carries EDNS flags. Changing a
// TTL does not invalidate RRSIGs, which hold the original TTL.
func capTTL(resp []byte, maxTTL uint32) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return resp
	}
	changed := false
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range section {
			h := &section[i].Header
			if h.Type != dnsmessage.TypeOPT && h.TTL > maxTTL {
				h.TTL = maxTTL
				changed = true
			}
		}
	}
	if !changed {
		return resp
	}
	out, err := m.Pack()
	if err != nil || len(out) > maxDNSMessage {
		return resp
	}
	return out
}

func parseQuery(query []byte) (queryInfo, bool) {
	var qi queryInfo
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return qi, false
	}
	qi.header = h
	questions, err := p.AllQuestions()
	if err != nil {
		qi.malformed = true
		return qi, true
	}
	qi.single = h.OpCode == 0 && len(questions) == 1 && questions[0].Class == dnsmessage.ClassINET
	if len(questions) > 0 {
		qi.question = questions[0]
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return qi, true
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			qi.edns = true
			qi.udpSize = int(rh.Class)
		}
		if p.SkipAdditional() != nil {
			break
		}
	}
	return qi, true
}

func responseHeader(qi queryInfo, rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{
		ID:                 qi.header.ID,
		Response:           true,
		OpCode:             qi.header.OpCode,
		RecursionDesired:   qi.header.RecursionDesired,
		RecursionAvailable: true,
		CheckingDisabled:   qi.header.CheckingDisabled,
		RCode:              rcode,
	}
}

func addEDNS(b *dnsmessage.Builder, qi queryInfo) error {
	if !qi.edns {
		return nil
	}
	if err := b.StartAdditionals(); err != nil {
		return err
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(ednsAdvertised, dnsmessage.RCodeSuccess, false); err != nil {
		return err
	}
	return b.OPTResource(rh, dnsmessage.OPTResource{})
}

func errorResponse(qi queryInfo, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, responseHeader(qi, rcode))
	if qi.single {
		if b.StartQuestions() != nil || b.Question(qi.question) != nil {
			return nil
		}
	}
	if addEDNS(&b, qi) != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// synthesize builds an authoritative-looking local answer for a peer FQDN. A
// peer without an address of the requested family gets NOERROR with no
// answers, so the other family is not negatively cached as NXDOMAIN.
func synthesize(qi queryInfo, addrs []netip.Addr, ttl uint32) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, responseHeader(qi, dnsmessage.RCodeSuccess))
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(qi.question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for i, a := range addrs {
		if i == maxSynthAnswers {
			break
		}
		rh := dnsmessage.ResourceHeader{Name: qi.question.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		var err error
		if a.Is4() {
			err = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		} else {
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	if err := addEDNS(&b, qi); err != nil {
		return nil, err
	}
	return b.Finish()
}

func addrOf(rr dnsmessage.Resource) (netip.Addr, bool) {
	switch body := rr.Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(body.A), true
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(body.AAAA), true
	}
	return netip.Addr{}, false
}

func addrResource(name dnsmessage.Name, a netip.Addr, ttl uint32) dnsmessage.Resource {
	rh := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}
	if a.Is4() {
		rh.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: rh, Body: &dnsmessage.AResource{A: a.As4()}}
	}
	rh.Type = dnsmessage.TypeAAAA
	return dnsmessage.Resource{Header: rh, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}}
}

func ownerName(n dnsmessage.Name) string {
	name, _ := normalizeDomain(n.String())
	return name
}

// rewrite applies the selected profile's peer mappings to an upstream answer.
// It only touches A/AAAA records of the queried type that belong to the
// query's CNAME chain. Addresses that are not online canonical peer addresses
// of the selected profile are preserved byte-for-byte in meaning. Any
// ambiguity, parse failure, or unexpected shape returns the upstream message
// unchanged.
func rewrite(resp []byte, qi queryInfo, qname string, profile *profileView, snap *peerSnapshot, maxTTL uint32) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return resp
	}
	if m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError {
		return resp
	}
	if len(m.Questions) != 1 || ownerName(m.Questions[0].Name) != qname || m.Questions[0].Type != qi.question.Type {
		return resp
	}
	qtype := qi.question.Type
	wantV6 := qtype == dnsmessage.TypeAAAA

	// Follow the CNAME chain from the query name within the answer section.
	chain := map[string]bool{qname: true}
	terminal := qname
	terminalName := m.Questions[0].Name
	for range maxCNAMEChain {
		next := ""
		var nextName dnsmessage.Name
		for _, rr := range m.Answers {
			if rr.Header.Type != dnsmessage.TypeCNAME || rr.Header.Class != dnsmessage.ClassINET || ownerName(rr.Header.Name) != terminal {
				continue
			}
			if body, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
				next, nextName = ownerName(body.CNAME), body.CNAME
			}
			break
		}
		if next == "" || chain[next] {
			break
		}
		chain[next] = true
		terminal, terminalName = next, nextName
	}

	changed := false
	rewritten := map[string]bool{}
	synthesizedOwner := ""

	// A CNAME chain that ends at an online peer FQDN of the selected profile
	// is completed from the peer map, even when public DNS cannot resolve it.
	if terminal != qname {
		if addrs, ok := profile.peer(terminal); ok {
			if eff := addrs.family(wantV6); len(eff) > 0 {
				kept := m.Answers[:0:0]
				for _, rr := range m.Answers {
					if rr.Header.Type == qtype && ownerName(rr.Header.Name) == terminal {
						continue
					}
					kept = append(kept, rr)
				}
				for i, a := range eff {
					if i == maxSynthAnswers {
						break
					}
					kept = append(kept, addrResource(terminalName, a, maxTTL))
				}
				m.Answers = kept
				m.RCode = dnsmessage.RCodeSuccess
				m.Authorities = nil
				rewritten[terminal] = true
				synthesizedOwner = terminal
				changed = true
			}
		}
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return resp
	}

	for i := range m.Answers {
		rr := &m.Answers[i]
		owner := ownerName(rr.Header.Name)
		if rr.Header.Type != qtype || rr.Header.Class != dnsmessage.ClassINET || !chain[owner] || owner == synthesizedOwner {
			continue
		}
		addr, ok := addrOf(*rr)
		if !ok {
			continue
		}
		effective, result := snap.translate(addr, profile.id)
		switch result {
		case notPeer:
			continue
		case ambiguous:
			return resp
		}
		if effective.Is6() != wantV6 {
			return resp
		}
		*rr = addrResource(rr.Header.Name, effective, min(rr.Header.TTL, maxTTL))
		rewritten[owner] = true
		changed = true
	}
	if !changed {
		return resp
	}

	// Signatures over rewritten RRsets no longer validate; drop them and
	// clear AD so clients do not treat the local answer as DNSSEC-secure.
	kept := m.Answers[:0:0]
	for _, rr := range m.Answers {
		if rr.Header.Type == typeRRSIG && rewritten[ownerName(rr.Header.Name)] {
			if body, ok := rr.Body.(*dnsmessage.UnknownResource); ok && len(body.Data) >= 2 &&
				dnsmessage.Type(binary.BigEndian.Uint16(body.Data)) == qtype {
				continue
			}
		}
		kept = append(kept, rr)
	}
	m.Answers = kept
	m.AuthenticData = false
	m.Authoritative = false
	out, err := m.Pack()
	if err != nil || len(out) > maxDNSMessage {
		return resp
	}
	return out
}

// fitResponse enforces the transport size limit. Oversized UDP answers become
// a header-and-question response with TC set so the client retries over TCP.
func fitResponse(resp []byte, qi queryInfo, limit int) []byte {
	if resp == nil || len(resp) <= limit {
		return resp
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return errorResponse(qi, dnsmessage.RCodeServerFailure)
	}
	h.Truncated = true
	b := dnsmessage.NewBuilder(nil, h)
	if qi.single {
		if b.StartQuestions() != nil || b.Question(qi.question) != nil {
			return nil
		}
	}
	if addEDNS(&b, qi) != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
