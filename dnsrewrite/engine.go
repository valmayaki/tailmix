// Package dnsrewrite answers DNS for public suffixes whose records point at
// tailnet peers. It forwards each query to an encrypted public resolver and,
// for suffixes bound to a profile, replaces canonical tailnet addresses in the
// answer with the effective addresses tailmix routes on this host.
//
// The engine serves classic DNS on an ephemeral loopback port so that the
// Tailscale DNS manager can use it as the resolver for those suffixes. Routes
// and peer data are swapped atomically by Update; queries never wait on the
// daemon, and the answer cache survives reconfiguration.
package dnsrewrite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Route binds a public DNS suffix to one profile, or all profiles when
// ProfileID is empty. The longest matching suffix wins.
type Route struct {
	Suffix    string
	ProfileID string
}

// Engine is a loopback DNS server that rewrites answers for bound suffixes.
type Engine struct {
	res    *resolver
	srv    *server
	udp    *net.UDPConn
	tcp    *net.TCPListener
	addr   netip.AddrPort
	cancel context.CancelFunc

	closeOnce sync.Once
	done      chan struct{}
}

// Start listens on 127.0.0.1 with one ephemeral port shared by UDP and TCP.
func Start(ctx context.Context, opts Options) (*Engine, error) {
	specs, err := parseUpstreams(opts.Upstreams)
	if err != nil {
		return nil, err
	}
	timeout := opts.UpstreamTimeout
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	maxTTL := opts.MaxAnswerTTL
	if maxTTL == 0 {
		maxTTL = DefaultMaxAnswerTTL
	}
	concurrent := opts.MaxConcurrent
	if concurrent <= 0 {
		concurrent = defaultMaxConcurrent
	}
	udp, tcp, err := listenLoopback()
	if err != nil {
		return nil, err
	}
	res := &resolver{fwd: newForwarder(specs, timeout), maxAnswerTTL: maxTTL}
	res.table.Store(&table{})
	engineCtx, cancel := context.WithCancel(ctx)
	e := &Engine{
		res:    res,
		srv:    newServer(res, len(specs), timeout, concurrent),
		udp:    udp,
		tcp:    tcp,
		addr:   udp.LocalAddr().(*net.UDPAddr).AddrPort(),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	var serving sync.WaitGroup
	serving.Add(2)
	go func() { defer serving.Done(); _ = e.srv.serveUDP(engineCtx, udp) }()
	go func() { defer serving.Done(); _ = e.srv.serveTCP(engineCtx, tcp) }()
	go func() {
		serving.Wait()
		e.srv.wg.Wait()
		close(e.done)
	}()
	return e, nil
}

// listenLoopback binds UDP to an ephemeral port and TCP to the same port,
// retrying when another process already holds that TCP port.
func listenLoopback() (*net.UDPConn, *net.TCPListener, error) {
	var errs []error
	for range 8 {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, nil, err
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			return udp, tcp, nil
		}
		_ = udp.Close()
		errs = append(errs, err)
	}
	return nil, nil, fmt.Errorf("bind DNS rewrite listener: %w", errors.Join(errs...))
}

// Addr is the loopback address serving both UDP and TCP.
func (e *Engine) Addr() netip.AddrPort { return e.addr }

// Update replaces the routes and peer data used for new queries. Routes with
// an invalid suffix are ignored. A route whose profile is absent
// from profiles is still matched: its answers pass through with capped TTLs.
func (e *Engine) Update(routes []Route, profiles []Profile) {
	t := &table{snap: buildSnapshot(profiles)}
	seen := map[string]bool{}
	for _, r := range routes {
		suffix, ok := normalizeDomain(r.Suffix)
		if !ok || suffix == "" || seen[suffix] {
			continue
		}
		seen[suffix] = true
		t.routes = append(t.routes, route{suffix: suffix, profileID: r.ProfileID})
	}
	sort.SliceStable(t.routes, func(i, j int) bool {
		return len(t.routes[i].suffix) > len(t.routes[j].suffix)
	})
	e.res.table.Store(t)
}

// Close stops serving and waits for in-flight queries to finish.
func (e *Engine) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.cancel()
		err = errors.Join(e.udp.Close(), e.tcp.Close())
		select {
		case <-e.done:
		case <-time.After(10 * time.Second):
		}
	})
	return err
}
