package dnsrewrite

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultUpstreamTimeout bounds one upstream attempt.
	DefaultUpstreamTimeout = 4 * time.Second
	// DefaultMaxAnswerTTL caps the TTL of answers that carry, or may carry,
	// a tailnet address. Effective addresses can be reassigned, and a raw
	// canonical address must not outlive missing peer data in OS caches.
	DefaultMaxAnswerTTL  = 10
	defaultMaxConcurrent = 128
	maxUpstreams         = 8
)

// Upstream is one encrypted public resolver. URL is https://host/path for DNS
// over HTTPS or tls://host[:port] for DNS over TLS; plaintext DNS is not
// supported. Bootstrap optionally lists IP literals to dial instead of
// resolving the URL host; the certificate is still verified against the host.
type Upstream struct {
	URL       string
	Bootstrap []string
}

// DefaultUpstreams are used when no upstream is configured. They are dialed
// by IP so the rewriting resolver never depends on the system resolver, which
// may itself point back at tailmix.
func DefaultUpstreams() []Upstream {
	return []Upstream{
		{URL: "https://cloudflare-dns.com/dns-query", Bootstrap: []string{"1.1.1.1", "1.0.0.1"}},
		{URL: "https://dns.quad9.net/dns-query", Bootstrap: []string{"9.9.9.9", "149.112.112.112"}},
	}
}

// Options configures an Engine. Zero values select the defaults.
type Options struct {
	Upstreams       []Upstream
	UpstreamTimeout time.Duration
	MaxAnswerTTL    uint32
	MaxConcurrent   int
}

type upstreamSpec struct {
	scheme     string // "https" or "tls"
	url        string // DoH endpoint
	serverName string // TLS certificate name
	hostPort   string // dial target when no bootstrap is configured
	bootstrap  []netip.AddrPort
}

func parseUpstreams(in []Upstream) ([]upstreamSpec, error) {
	if len(in) == 0 {
		in = DefaultUpstreams()
	}
	if len(in) > maxUpstreams {
		return nil, fmt.Errorf("configure at most %d encrypted upstreams", maxUpstreams)
	}
	specs := make([]upstreamSpec, 0, len(in))
	for i, u := range in {
		spec, err := parseUpstream(u)
		if err != nil {
			return nil, fmt.Errorf("upstream %d: %w", i, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func parseUpstream(u Upstream) (upstreamSpec, error) {
	parsed, err := url.Parse(u.URL)
	if err != nil {
		return upstreamSpec{}, err
	}
	if parsed.User != nil {
		return upstreamSpec{}, errors.New("upstream URLs must not contain credentials")
	}
	host := parsed.Hostname()
	if host == "" {
		return upstreamSpec{}, errors.New("upstream URL needs a host")
	}
	spec := upstreamSpec{scheme: parsed.Scheme, serverName: host}
	port := parsed.Port()
	switch parsed.Scheme {
	case "https":
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return upstreamSpec{}, errors.New("DoH URL must not contain a query or fragment")
		}
		if port == "" {
			port = "443"
		}
		spec.url = parsed.String()
	case "tls":
		if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
			return upstreamSpec{}, errors.New("DoT URL must be tls://host[:port]")
		}
		if port == "" {
			port = "853"
		}
	default:
		return upstreamSpec{}, errors.New("upstream scheme must be https (DoH) or tls (DoT)")
	}
	spec.hostPort = net.JoinHostPort(host, port)
	var portNum uint16
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil || portNum == 0 {
		return upstreamSpec{}, errors.New("invalid upstream port")
	}
	for _, b := range u.Bootstrap {
		addr, err := netip.ParseAddr(b)
		if err != nil {
			return upstreamSpec{}, fmt.Errorf("bootstrap must be IP literals: %w", err)
		}
		spec.bootstrap = append(spec.bootstrap, netip.AddrPortFrom(addr.Unmap(), portNum))
	}
	return spec, nil
}

// normalizeDomain lowercases a name and strips one trailing dot. It reports
// false for names that are not plain DNS host names.
func normalizeDomain(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", true
	}
	if len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return name, true
}
