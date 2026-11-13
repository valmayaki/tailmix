package dnsrewrite

import "net/netip"

// Profile is one running profile's online peers, as supplied by tailmixd.
type Profile struct {
	ID    string
	Peers []Peer
}

// Peer maps an online peer's MagicDNS name to its address pairs.
type Peer struct {
	DNSName   string
	Addresses []AddressPair
}

// AddressPair is a peer's canonical tailnet address and the effective address
// the host routes for it.
type AddressPair struct {
	Canonical netip.Addr
	Effective netip.Addr
}

// peerSnapshot is an immutable index of the supplied profiles.
type peerSnapshot struct {
	byID        map[string]*profileView
	byCanonical map[netip.Addr][]addrOwner
}

type profileView struct {
	id string
	// peers maps a normalized FQDN to its effective addresses. A nil value
	// marks a name reported more than once, which is never synthesized.
	peers map[string]*peerAddrs
}

type peerAddrs struct {
	v4, v6 []netip.Addr
}

type addrOwner struct {
	profileID string
	effective netip.Addr
}

// translation is the outcome of looking up one upstream answer address.
type translation int

const (
	notPeer translation = iota
	translated
	ambiguous
)

// profile returns the running profile with this ID, or nil.
func (s *peerSnapshot) profile(id string) *profileView {
	if s == nil {
		return nil
	}
	return s.byID[id]
}

// peerAcross returns a peer only when its DNS name has one unambiguous owner.
func (s *peerSnapshot) peerAcross(name string) (*peerAddrs, bool) {
	if s == nil {
		return nil, false
	}
	var found *peerAddrs
	for _, profile := range s.byID {
		if addrs, present := profile.peers[name]; present {
			if found != nil || addrs == nil {
				return nil, false
			}
			found = addrs
		}
	}
	return found, found != nil
}

func (p *profileView) peer(name string) (*peerAddrs, bool) {
	if p == nil {
		return nil, false
	}
	addrs, ok := p.peers[name]
	return addrs, ok && addrs != nil
}

func (a *peerAddrs) family(v6 bool) []netip.Addr {
	if v6 {
		return a.v6
	}
	return a.v4
}

// translate maps a canonical address seen in a public answer to an effective
// address. A nonempty profileID restricts the mapping to that profile.
func (s *peerSnapshot) translate(addr netip.Addr, profileID string) (netip.Addr, translation) {
	owners := s.byCanonical[addr.Unmap()]
	if len(owners) == 0 {
		return netip.Addr{}, notPeer
	}
	effective := owners[0].effective
	for _, o := range owners {
		if (profileID != "" && o.profileID != profileID) || o.effective != effective {
			return netip.Addr{}, ambiguous
		}
	}
	return effective, translated
}

func buildSnapshot(profiles []Profile) *peerSnapshot {
	s := &peerSnapshot{
		byID:        map[string]*profileView{},
		byCanonical: map[netip.Addr][]addrOwner{},
	}
	for _, p := range profiles {
		if p.ID == "" || s.byID[p.ID] != nil {
			continue
		}
		view := &profileView{id: p.ID, peers: map[string]*peerAddrs{}}
		for _, peer := range p.Peers {
			name, ok := normalizeDomain(peer.DNSName)
			if !ok || name == "" {
				continue
			}
			addrs := &peerAddrs{}
			for _, a := range peer.Addresses {
				canonical, effective := a.Canonical.Unmap(), a.Effective.Unmap()
				if !canonical.IsValid() || !effective.IsValid() || canonical.Is4() != effective.Is4() {
					continue
				}
				s.byCanonical[canonical] = append(s.byCanonical[canonical], addrOwner{profileID: p.ID, effective: effective})
				if effective.Is4() {
					addrs.v4 = append(addrs.v4, effective)
				} else {
					addrs.v6 = append(addrs.v6, effective)
				}
			}
			if len(addrs.v4) == 0 && len(addrs.v6) == 0 {
				continue
			}
			if _, dup := view.peers[name]; dup {
				view.peers[name] = nil
				continue
			}
			view.peers[name] = addrs
		}
		s.byID[p.ID] = view
	}
	return s
}
