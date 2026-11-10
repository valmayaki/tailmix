package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

// blockingStatusEngine reports a running profile until block is set, after
// which Status waits for its context like a wedged LocalAPI would.
type blockingStatusEngine struct {
	lifecycleEngine
	block bool
	calls int
}

func (e *blockingStatusEngine) Status(ctx context.Context) (tailmixprofile.Status, error) {
	e.calls++
	if e.block {
		<-ctx.Done()
		return tailmixprofile.Status{}, ctx.Err()
	}
	return e.status, nil
}

func dnsPeersTestSupervisor(t *testing.T) (*supervisor, *blockingStatusEngine) {
	t.Helper()
	st := lifecycleTestState()
	st.Leases = []state.EffectiveLease{{
		ProfileID: "p_work", NodeID: "n1",
		CanonicalIP: netip.MustParseAddr("100.64.0.3"), EffectiveIP: netip.MustParseAddr("100.127.0.25"),
	}}
	s := newLifecycleTestSupervisor(t, st)
	s.cfg.Mode = "tun"
	engine := &blockingStatusEngine{lifecycleEngine: lifecycleEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running", MagicDNSSuffix: "ts.example.",
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "n1", DNSName: "ishiro.ts.example.", Online: true,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		}},
	}}}
	s.runtimes["p_work"] = &managedProfile{runtime: runtimeProfile{State: st.Profiles[0], Engine: engine}}
	return s, engine
}

func refreshDNSPeers(s *supervisor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statusesLocked()
	s.publishDNSPeersLocked()
}

func TestDNSPeersReportsPublishedLeases(t *testing.T) {
	s, _ := dnsPeersTestSupervisor(t)
	refreshDNSPeers(s)
	got, err := s.DNSPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "work" || len(got.Profiles[0].Peers) != 1 {
		t.Fatalf("DNSPeers = %+v", got)
	}
	peer := got.Profiles[0].Peers[0]
	if peer.DNSName != "ishiro.ts.example" || len(peer.Addresses) != 1 ||
		peer.Addresses[0].EffectiveIP != netip.MustParseAddr("100.127.0.25") {
		t.Fatalf("peer = %+v", peer)
	}
}

// The resolver polls DNSPeers with a short deadline. Reconciliation holds the
// supervisor lock across LocalAPI calls, route changes and OS DNS updates, so
// the read must never wait for that lock or call a profile itself.
func TestDNSPeersDoesNotWaitForSupervisorLock(t *testing.T) {
	s, engine := dnsPeersTestSupervisor(t)
	refreshDNSPeers(s)
	calls := engine.calls

	s.mu.Lock()
	defer s.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		got, _ := s.DNSPeers(context.Background())
		done <- len(got.Profiles)
	}()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("DNSPeers returned %d profiles while reconciling, want the published 1", n)
		}
	case <-time.After(time.Second):
		t.Fatal("DNSPeers blocked on the supervisor lock")
	}
	if engine.calls != calls {
		t.Fatalf("DNSPeers called profile Status %d time(s)", engine.calls-calls)
	}
}

func TestDNSPeersBeforeFirstReconcileIsEmpty(t *testing.T) {
	s, _ := dnsPeersTestSupervisor(t)
	got, err := s.DNSPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Profiles == nil || len(got.Profiles) != 0 {
		t.Fatalf("DNSPeers = %+v, want an empty profile list", got)
	}
}

func TestDNSPeersOmitsProfileWithStaleStatus(t *testing.T) {
	s, engine := dnsPeersTestSupervisor(t)
	refreshDNSPeers(s)
	engine.block = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.ctx = ctx
	refreshDNSPeers(s)
	got, _ := s.DNSPeers(context.Background())
	if len(got.Profiles) != 0 {
		t.Fatalf("DNSPeers kept a profile whose status could not be refreshed: %+v", got)
	}
}

func TestDNSPeersEmptyWhenDown(t *testing.T) {
	s, _ := dnsPeersTestSupervisor(t)
	refreshDNSPeers(s)
	s.mu.Lock()
	s.st.Down = true
	s.publishDNSPeersLocked()
	s.mu.Unlock()
	if got, _ := s.DNSPeers(context.Background()); len(got.Profiles) != 0 {
		t.Fatalf("DNSPeers = %+v while down", got)
	}
}

// A wedged profile LocalAPI must not hold the supervisor lock indefinitely.
func TestStatusesLockedBoundsProfileStatusCalls(t *testing.T) {
	s, engine := dnsPeersTestSupervisor(t)
	refreshDNSPeers(s)
	engine.block = true
	s.statusTimeout = 50 * time.Millisecond

	start := time.Now()
	s.mu.Lock()
	statuses := s.statusesLocked()
	s.mu.Unlock()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("statusesLocked took %v with a wedged profile", elapsed)
	}
	if s.runtimes["p_work"].statusFresh {
		t.Fatal("timed-out status marked fresh")
	}
	if len(statuses) != 1 || statuses[0].ProfileID != "p_work" {
		t.Fatalf("statuses = %+v, want the cached status", statuses)
	}
	if s.lastErrors["p_work"] != context.DeadlineExceeded.Error() {
		t.Fatalf("profile error = %q, want the status timeout", s.lastErrors["p_work"])
	}
}
