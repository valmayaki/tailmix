package main

import (
	"context"
	"fmt"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/dnsrewrite"
	"github.com/maisem/tailmix/state"
	"tailscale.com/types/dnstype"
)

// DNS rewrites resolve a public suffix (for example a company domain whose
// records point at canonical tailnet addresses) through an encrypted public
// resolver, then replace canonical addresses of the bound profile's online
// peers with the effective addresses this host routes. One rewriting engine
// lives as long as the daemon so its answer cache survives reconciliation;
// routes and peer data are swapped into it without blocking queries.

const (
	dnsRewriteActive   = "active"
	dnsRewriteWaiting  = "waiting"
	dnsRewriteInactive = "inactive"
)

func (s *supervisor) DNSRewrites(_ context.Context) (controlapi.DNSRewrites, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsRewritesLocked(), nil
}

func (s *supervisor) PatchDNSRewrites(_ context.Context, request controlapi.PatchDNSRewritesRequest) (controlapi.DNSRewrites, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	if err := applyDNSRewritePatch(&next, request); err != nil {
		return controlapi.DNSRewrites{}, err
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.DNSRewrites{}, err
	}
	return s.dnsRewritesLocked(), nil
}

func applyDNSRewritePatch(next *state.State, request controlapi.PatchDNSRewritesRequest) error {
	for _, mutation := range request.Remove {
		domain, err := canonicalDNSDomain(mutation.Domain, false)
		if err != nil {
			return err
		}
		index := dnsRewriteIndex(next.DNSRewrites, domain)
		if index < 0 {
			continue
		}
		if mutation.ProfileName != "" {
			configured, err := profileByName(next, mutation.ProfileName)
			if err != nil {
				return err
			}
			if next.DNSRewrites[index].ProfileID != configured.ID {
				return controlapi.NewError("binding_profile_mismatch",
					"DNS rewrite %q belongs to profile %q, not %q",
					domain, profileNameByID(*next, next.DNSRewrites[index].ProfileID), mutation.ProfileName)
			}
		}
		next.DNSRewrites = append(next.DNSRewrites[:index], next.DNSRewrites[index+1:]...)
	}
	for _, mutation := range request.Add {
		domain, err := canonicalDNSDomain(mutation.Domain, false)
		if err != nil {
			return err
		}
		profileID := ""
		if mutation.ProfileName != "" {
			configured, err := profileByName(next, mutation.ProfileName)
			if err != nil {
				return err
			}
			if configured.Removed {
				return controlapi.NewError("profile_not_found", "profile %q is removed", mutation.ProfileName)
			}
			profileID = configured.ID
		}
		index := dnsRewriteIndex(next.DNSRewrites, domain)
		if index >= 0 {
			existing := next.DNSRewrites[index]
			if existing.ProfileID == profileID {
				continue
			}
			if !request.Replace {
				return controlapi.NewError("dns_rewrite_conflict",
					"DNS rewrite %q already belongs to profile %q; pass --replace to override it",
					domain, profileNameByID(*next, existing.ProfileID))
			}
			next.DNSRewrites[index].ProfileID = profileID
			continue
		}
		next.DNSRewrites = append(next.DNSRewrites, state.DNSRewrite{Domain: domain, ProfileID: profileID})
	}
	state.Normalize(next)
	return nil
}

func dnsRewriteIndex(rewrites []state.DNSRewrite, domain string) int {
	for i, rewrite := range rewrites {
		if rewrite.Domain == domain {
			return i
		}
	}
	return -1
}

// dnsRewritesLocked reports each configured rewrite against what the last
// successful DNS configuration installed.
func (s *supervisor) dnsRewritesLocked() controlapi.DNSRewrites {
	result := controlapi.DNSRewrites{Rewrites: []controlapi.DNSRewrite{}, ReconcileError: s.reconcileErr}
	installed := map[string]bool{}
	for _, route := range s.dnsRewriteRoutes {
		installed[route.Suffix] = true
	}
	running := map[string]bool{}
	if published := s.dnsPeers.Load(); published != nil {
		for _, profile := range published.Profiles {
			running[profile.ID] = true
		}
	}
	for _, rewrite := range s.st.DNSRewrites {
		entry := controlapi.DNSRewrite{
			Domain:      rewrite.Domain,
			ProfileID:   rewrite.ProfileID,
			ProfileName: profileNameByID(s.st, rewrite.ProfileID),
		}
		switch {
		case s.cfg.Mode != "tun":
			entry.State, entry.Reason = dnsRewriteInactive, "DNS rewrites require TUN mode"
		case s.st.Down:
			entry.State, entry.Reason = dnsRewriteInactive, "tailmix is down"
		case !installed[rewrite.Domain]:
			entry.State, entry.Reason = dnsRewriteInactive, "another DNS route owns this suffix"
		case rewrite.ProfileID != "" && !running[rewrite.ProfileID]:
			entry.State, entry.Reason = dnsRewriteWaiting, "profile is not running; answers pass through with short TTLs"
		default:
			entry.State = dnsRewriteActive
		}
		result.Rewrites = append(result.Rewrites, entry)
	}
	return result
}

// dnsRewriteResolverLocked returns the loopback resolver for rewrite routes,
// starting the engine on first use.
func (s *supervisor) dnsRewriteResolverLocked() (*dnstype.Resolver, error) {
	if s.dnsRewrite == nil {
		engine, err := dnsrewrite.Start(s.ctx, dnsrewrite.Options{})
		if err != nil {
			return nil, fmt.Errorf("start DNS rewrite resolver: %w", err)
		}
		s.dnsRewrite = engine
	}
	return &dnstype.Resolver{Addr: s.dnsRewrite.Addr().String()}, nil
}

// updateDNSRewriteLocked pushes the installed rewrite routes and the
// published peer view into the engine.
func (s *supervisor) updateDNSRewriteLocked() {
	if s.dnsRewrite == nil {
		return
	}
	var profiles []dnsrewrite.Profile
	if published := s.dnsPeers.Load(); published != nil {
		profiles = dnsRewriteProfiles(*published)
	}
	s.dnsRewrite.Update(s.dnsRewriteRoutes, profiles)
}

func dnsRewriteProfiles(peers controlapi.DNSPeers) []dnsrewrite.Profile {
	profiles := make([]dnsrewrite.Profile, 0, len(peers.Profiles))
	for _, p := range peers.Profiles {
		profile := dnsrewrite.Profile{ID: p.ID, Peers: make([]dnsrewrite.Peer, 0, len(p.Peers))}
		for _, peer := range p.Peers {
			converted := dnsrewrite.Peer{DNSName: peer.DNSName}
			for _, addr := range peer.Addresses {
				converted.Addresses = append(converted.Addresses, dnsrewrite.AddressPair{
					Canonical: addr.CanonicalIP,
					Effective: addr.EffectiveIP,
				})
			}
			profile.Peers = append(profile.Peers, converted)
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func (s *supervisor) closeDNSRewriteLocked() {
	if s.dnsRewrite != nil {
		_ = s.dnsRewrite.Close()
		s.dnsRewrite = nil
	}
	s.dnsRewriteRoutes = nil
}

var _ controlapi.DNSRewriteBackend = (*supervisor)(nil)
