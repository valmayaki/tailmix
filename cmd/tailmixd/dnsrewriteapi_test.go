package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maisem/tailmix/controlapi"
	tailmixdns "github.com/maisem/tailmix/dns"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/routingpolicy"
	"github.com/maisem/tailmix/state"
	"golang.org/x/net/dns/dnsmessage"
)

func TestApplyDNSRewritePatch(t *testing.T) {
	st := testPolicyState()
	add := func(domain, profile string, replace bool) error {
		return applyDNSRewritePatch(&st, controlapi.PatchDNSRewritesRequest{
			Add: []controlapi.DNSRouteMutation{{Domain: domain, ProfileName: profile}}, Replace: replace,
		})
	}
	if err := add(" Shekel.Africa. ", "work", false); err != nil {
		t.Fatal(err)
	}
	if len(st.DNSRewrites) != 1 || st.DNSRewrites[0] != (state.DNSRewrite{Domain: "shekel.africa", ProfileID: "p_work"}) {
		t.Fatalf("rewrites = %+v", st.DNSRewrites)
	}
	if err := add("shekel.africa", "work", false); err != nil {
		t.Fatalf("re-adding the same rewrite: %v", err)
	}
	var apiErr *controlapi.Error
	if err := add("shekel.africa", "lab", false); !errors.As(err, &apiErr) || apiErr.Code != "dns_rewrite_conflict" {
		t.Fatalf("conflicting add err = %v, want dns_rewrite_conflict", err)
	}
	if err := add("shekel.africa", "lab", true); err != nil || st.DNSRewrites[0].ProfileID != "p_lab" {
		t.Fatalf("replace err = %v, rewrites = %+v", err, st.DNSRewrites)
	}
	if err := add(".", "lab", false); err == nil {
		t.Fatal("root suffix accepted as a rewrite")
	}
	if err := add("x.example", "missing", false); err == nil {
		t.Fatal("unknown profile accepted")
	}
	err := applyDNSRewritePatch(&st, controlapi.PatchDNSRewritesRequest{
		Remove: []controlapi.DNSRouteUnbind{{Domain: "shekel.africa", ProfileName: "work"}},
	})
	if !errors.As(err, &apiErr) || apiErr.Code != "binding_profile_mismatch" {
		t.Fatalf("mismatched remove err = %v", err)
	}
	if err := applyDNSRewritePatch(&st, controlapi.PatchDNSRewritesRequest{
		Remove: []controlapi.DNSRouteUnbind{{Domain: "SHEKEL.africa."}},
	}); err != nil || len(st.DNSRewrites) != 0 {
		t.Fatalf("remove err = %v, rewrites = %+v", err, st.DNSRewrites)
	}
}

func TestTunDNSLiveConfigAddsRewriteRoutesWithLowestPrecedence(t *testing.T) {
	statuses := dnsRewriteTestStatuses()
	st := dnsRewriteTestState(t)
	st.DNSRewrites = []state.DNSRewrite{
		{Domain: "shekel.example", ProfileID: "p_work"},
		// The work profile's MagicDNS suffix already has an automatic route.
		{Domain: "work.ts.net", ProfileID: "p_work"},
	}
	leases, _, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tunDNSLiveConfig(st, statuses, leases, routingpolicy.BuildDNS(st, statuses))
	if err != nil {
		t.Fatal(err)
	}
	bySuffix := map[string]tailmixdns.Route{}
	for _, route := range cfg.Routes {
		bySuffix[route.Suffix] = route
	}
	if got := bySuffix["shekel.example"]; !got.Rewrite || got.ProfileID != "p_work" {
		t.Errorf("shekel.example route = %+v, want a work rewrite", got)
	}
	if got, ok := bySuffix["work.ts.net"]; !ok || got.Rewrite {
		t.Errorf("work.ts.net route = %+v (present %v), want the automatic route kept", got, ok)
	}
}

func TestDNSRewriteEngineServesPublishedPeers(t *testing.T) {
	s, _ := dnsPeersTestSupervisor(t)
	dnsService := &recordingDNSService{}
	s.dnsService = dnsService
	t.Cleanup(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closeDNSRewriteLocked()
	})
	s.st.DNSRewrites = []state.DNSRewrite{{Domain: "ts.example", ProfileID: "p_work"}}

	s.mu.Lock()
	err := s.configureDNSLocked(tailmixdns.LiveConfig{Routes: []tailmixdns.Route{
		{Suffix: "ts.example", ProfileID: "p_work", Rewrite: true},
	}})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(dnsService.cfg.Routes) != 1 || len(dnsService.cfg.Routes[0].Resolvers) != 1 ||
		dnsService.cfg.Routes[0].Resolvers[0].Addr != s.dnsRewrite.Addr().String() {
		t.Fatalf("installed routes = %+v, want the rewrite resolver %v", dnsService.cfg.Routes, s.dnsRewrite.Addr())
	}

	// Before peers are published the profile is waiting.
	if got := s.dnsRewritesLocked().Rewrites[0].State; got != dnsRewriteWaiting {
		t.Fatalf("state before publish = %q, want %q", got, dnsRewriteWaiting)
	}
	refreshDNSPeers(s)
	got, err := s.DNSRewrites(context.Background())
	if err != nil || len(got.Rewrites) != 1 || got.Rewrites[0].State != dnsRewriteActive || got.Rewrites[0].ProfileName != "work" {
		t.Fatalf("DNSRewrites = %+v, %v", got, err)
	}

	// The online peer is answered from the published peer view without any
	// upstream query.
	answer := queryA(t, s.dnsRewrite.Addr(), "ishiro.ts.example.")
	if answer != netip.MustParseAddr("100.127.0.25") {
		t.Fatalf("answer = %v, want the effective address", answer)
	}

	// The engine and its cache survive reconfiguration.
	engine := s.dnsRewrite
	s.mu.Lock()
	err = s.configureDNSLocked(dnsService.cfg)
	s.mu.Unlock()
	if err != nil || s.dnsRewrite != engine {
		t.Fatalf("reconfigure err = %v, engine replaced = %v", err, s.dnsRewrite != engine)
	}
}

func TestDNSRewritesReportInactiveOutsideTUNMode(t *testing.T) {
	s := &supervisor{st: testPolicyState()}
	s.st.DNSRewrites = []state.DNSRewrite{{Domain: "shekel.example", ProfileID: "p_work"}}
	s.cfg.Mode = "socks"
	got := s.dnsRewritesLocked()
	if len(got.Rewrites) != 1 || got.Rewrites[0].State != dnsRewriteInactive || got.Rewrites[0].Reason == "" {
		t.Fatalf("rewrites = %+v", got.Rewrites)
	}
}

func dnsRewriteTestStatuses() []tailmixprofile.Status {
	return []tailmixprofile.Status{{
		ProfileID:      "p_work",
		MagicDNSSuffix: "work.ts.net",
		SelfNodeID:     "work-self",
		SelfDNSName:    "tailmix.work.ts.net",
		SelfIPs:        []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID:       "work-peer",
			DNSName:      "ishiro.work.ts.net",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		}},
	}}
}

func dnsRewriteTestState(t *testing.T) state.State {
	t.Helper()
	st := testPolicyState()
	if err := ensureHostIPs(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// recordingDNSService records the last configuration it was given.
type recordingDNSService struct {
	cfg tailmixdns.LiveConfig
}

func (r *recordingDNSService) Addr() netip.AddrPort                                     { return netip.AddrPort{} }
func (r *recordingDNSService) Configure([]tailmixdns.Domain, []tailmixdns.Record) error { return nil }
func (r *recordingDNSService) ConfigureFull(cfg tailmixdns.LiveConfig) error {
	r.cfg = cfg
	return nil
}
func (r *recordingDNSService) HandlePacket([]byte) bool { return false }
func (r *recordingDNSService) Outbound() <-chan []byte  { return nil }
func (r *recordingDNSService) Err() error               { return nil }
func (r *recordingDNSService) Close() error             { return nil }

func queryA(t *testing.T, server netip.AddrPort, name string) netip.Addr {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(a.A)
		}
	}
	t.Fatalf("no A answer: rcode %v", m.RCode)
	return netip.Addr{}
}
