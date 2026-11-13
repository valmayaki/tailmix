package main

import (
	"context"
	"net/netip"
	"sort"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/effectiveip"
	"github.com/maisem/tailmix/routingpolicy"
)

// DNSPeers reports the online peers of running profiles together with the
// effective addresses the host currently routes for them. Only TUN mode
// installs host routes for effective addresses, so SOCKS mode reports no
// profiles. Peers without a reconciled lease are omitted rather than guessed.
//
// The view is published at the end of every reconciliation, so the read never
// takes the supervisor lock or calls a profile LocalAPI. Reconciliation holds
// that lock across LocalAPI calls, route changes and OS DNS updates; a reader
// that waited for it would miss the short deadline a DNS resolver can afford.
func (s *supervisor) DNSPeers(_ context.Context) (controlapi.DNSPeers, error) {
	if published := s.dnsPeers.Load(); published != nil {
		return *published, nil
	}
	return controlapi.DNSPeers{Profiles: []controlapi.DNSPeerProfile{}}, nil
}

// publishDNSPeersLocked projects the cached profile statuses and the current
// leases for DNSPeers. It makes no LocalAPI calls. The published value is
// never mutated afterwards.
func (s *supervisor) publishDNSPeersLocked() {
	peers := s.dnsPeersLocked()
	s.dnsPeers.Store(&peers)
	s.updateDNSRewriteLocked()
}

func (s *supervisor) dnsPeersLocked() controlapi.DNSPeers {
	result := controlapi.DNSPeers{Profiles: []controlapi.DNSPeerProfile{}}
	if s.st.Down || s.cfg.Mode != "tun" {
		return result
	}
	effective := make(map[effectiveip.NodeKey]netip.Addr, len(s.st.Leases))
	for _, lease := range leasesFromState(s.st.Leases) {
		effective[lease.NodeKey] = lease.EffectiveIP
	}
	for _, configured := range s.st.Profiles {
		if configured.Disabled || configured.Removed {
			continue
		}
		managed := s.runtimes[configured.ID]
		if managed == nil || !managed.statusFresh {
			continue
		}
		status := managed.status
		if status.ProfileID == "" || status.BackendState != "Running" {
			continue
		}
		profile := controlapi.DNSPeerProfile{
			ID:             status.ProfileID,
			Name:           s.nameForIDLocked(status.ProfileID),
			MagicDNSSuffix: routingpolicy.NormalizeDomain(status.MagicDNSSuffix),
			Peers:          []controlapi.DNSPeer{},
		}
		for _, peer := range status.Peers {
			name := routingpolicy.NormalizeDomain(peer.DNSName)
			if !peer.Online || peer.NodeID == "" || name == "" || name == "." {
				continue
			}
			var addresses []controlapi.DNSPeerAddress
			for _, canonical := range peer.TailscaleIPs {
				key := effectiveip.NodeKey{ProfileID: status.ProfileID, NodeID: peer.NodeID, CanonicalIP: canonical}
				ip, ok := effective[key]
				if !ok {
					continue
				}
				addresses = append(addresses, controlapi.DNSPeerAddress{CanonicalIP: canonical, EffectiveIP: ip})
			}
			if len(addresses) == 0 {
				continue
			}
			profile.Peers = append(profile.Peers, controlapi.DNSPeer{
				DNSName:   name,
				Online:    true,
				Addresses: addresses,
			})
		}
		sort.Slice(profile.Peers, func(i, j int) bool { return profile.Peers[i].DNSName < profile.Peers[j].DNSName })
		result.Profiles = append(result.Profiles, profile)
	}
	sort.Slice(result.Profiles, func(i, j int) bool { return result.Profiles[i].Name < result.Profiles[j].Name })
	return result
}

var _ controlapi.DNSPeerBackend = (*supervisor)(nil)
