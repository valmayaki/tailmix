package dnsrewrite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDNSMessage = 65535
	dnsHeaderLen  = 12
	// hedgeDelay is how long an upstream may run before the next one is
	// queried in parallel; the first valid answer wins.
	hedgeDelay = 300 * time.Millisecond
	// dohIdleConnTimeout keeps the DoH connection warm between bursts so a
	// query after a quiet minute does not pay a fresh TCP and TLS handshake.
	dohIdleConnTimeout = 5 * time.Minute
	// dohPingInterval and dohPingTimeout detect connections that died
	// silently (NAT expiry, sleep, Wi-Fi roam) before a query waits on them.
	dohPingInterval = 15 * time.Second
	dohPingTimeout  = 5 * time.Second
)

// upstream exchanges one wire-format DNS message over an encrypted transport.
type upstream interface {
	exchange(ctx context.Context, query []byte) ([]byte, error)
}

// forwarder answers from its cache when it can, and otherwise queries the
// configured upstreams in order, starting the next one when the current one
// fails or exceeds hedgeDelay. Each upstream has its own bounded deadline,
// and every answer is validated against the query.
type forwarder struct {
	upstreams  []upstream
	timeout    time.Duration
	hedgeDelay time.Duration
	cache      *answerCache
}

func newForwarder(specs []upstreamSpec, timeout time.Duration) *forwarder {
	f := &forwarder{timeout: timeout, hedgeDelay: hedgeDelay, cache: newAnswerCache()}
	for _, spec := range specs {
		dial := bootstrapDialer(spec, timeout)
		switch spec.scheme {
		case "https":
			f.upstreams = append(f.upstreams, newDoH(spec, dial, timeout))
		case "tls":
			f.upstreams = append(f.upstreams, &dotUpstream{spec: spec, dial: dial})
		}
	}
	return f
}

func (f *forwarder) forward(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < dnsHeaderLen {
		return nil, errors.New("short query")
	}
	clientID := binary.BigEndian.Uint16(query)
	key, questions, cacheable := keyFor(query)
	if cacheable {
		if resp, stale, ok := f.cache.lookup(key, questions); ok {
			if stale && f.cache.beginRefresh(key) {
				go f.refresh(key, bytes.Clone(query))
			}
			binary.BigEndian.PutUint16(resp, clientID)
			return resp, nil
		}
	}
	resp, err := f.exchange(ctx, query)
	if err != nil {
		return nil, err
	}
	if cacheable {
		f.cache.store(key, resp)
	}
	binary.BigEndian.PutUint16(resp, clientID)
	return resp, nil
}

// refresh replaces a stale cache entry. It runs detached from the client
// query, bounded by the same worst case as a foreground lookup.
func (f *forwarder) refresh(key cacheKey, query []byte) {
	defer f.cache.endRefresh(key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(f.upstreams))*f.timeout)
	defer cancel()
	if resp, err := f.exchange(ctx, query); err == nil {
		f.cache.store(key, resp)
	}
}

// exchange returns the first valid upstream answer. Upstreams start in
// configured order: the next one starts when the previous fails or after
// hedgeDelay, so one slow or dead upstream costs at most hedgeDelay.
func (f *forwarder) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(f.upstreams) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the losers
	type result struct {
		resp []byte
		err  error
	}
	results := make(chan result, len(f.upstreams))
	next, pending := 0, 0
	start := func() {
		u := f.upstreams[next]
		next++
		pending++
		go func() {
			uctx, ucancel := context.WithTimeout(ctx, f.timeout)
			defer ucancel()
			resp, err := u.exchange(uctx, query)
			if err == nil {
				err = checkResponse(query, resp)
			}
			results <- result{resp, err}
		}()
	}
	start()
	hedge := time.NewTimer(f.hedgeDelay)
	defer hedge.Stop()
	var errs []error
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				return r.resp, nil
			}
			errs = append(errs, r.err)
			if next < len(f.upstreams) {
				start()
				hedge.Reset(f.hedgeDelay)
			}
		case <-hedge.C:
			if next < len(f.upstreams) {
				start()
				hedge.Reset(f.hedgeDelay)
			}
		case <-ctx.Done():
			return nil, errors.Join(append(errs, ctx.Err())...)
		}
	}
	return nil, errors.Join(errs...)
}

// checkResponse rejects messages that are not responses to the exact question
// that was sent.
func checkResponse(query, resp []byte) error {
	if len(resp) < dnsHeaderLen || len(resp) > maxDNSMessage {
		return errors.New("upstream returned a malformed DNS message")
	}
	var qp, rp dnsmessage.Parser
	qh, err := qp.Start(query)
	if err != nil {
		return err
	}
	rh, err := rp.Start(resp)
	if err != nil {
		return errors.New("upstream returned a malformed DNS message")
	}
	if !rh.Response || rh.OpCode != qh.OpCode {
		return errors.New("upstream returned a non-response")
	}
	qq, err := qp.AllQuestions()
	if err != nil {
		return err
	}
	rq, err := rp.AllQuestions()
	if err != nil {
		return errors.New("upstream returned a malformed question")
	}
	if len(qq) != len(rq) {
		return errors.New("upstream answered a different question")
	}
	for i := range qq {
		if qq[i].Type != rq[i].Type || qq[i].Class != rq[i].Class ||
			!strings.EqualFold(qq[i].Name.String(), rq[i].Name.String()) {
			return errors.New("upstream answered a different question")
		}
	}
	return nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// bootstrapDialer dials the configured bootstrap IPs in order, or the URL host
// through the system resolver when none are configured. TLS verification is
// always performed against the URL host name by the caller.
func bootstrapDialer(spec upstreamSpec, timeout time.Duration) dialFunc {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if len(spec.bootstrap) == 0 {
		return d.DialContext
	}
	targets := make([]string, len(spec.bootstrap))
	for i, ap := range spec.bootstrap {
		targets[i] = ap.String()
	}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var errs []error
		for _, t := range targets {
			c, err := d.DialContext(ctx, network, t)
			if err == nil {
				return c, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

type dohUpstream struct {
	url    string
	client *http.Client
}

func newDoH(spec upstreamSpec, dial dialFunc, timeout time.Duration) *dohUpstream {
	transport := &http.Transport{
		// Never pick up environment or corporate proxy settings.
		Proxy:                  nil,
		DialContext:            dial,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        dohIdleConnTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: dohPingInterval,
			PingTimeout:     dohPingTimeout,
		},
	}
	return &dohUpstream{
		url: spec.url,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("DoH redirects are not followed")
			},
		},
	}
}

func (u *dohUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	// RFC 8484 recommends ID 0 so HTTP caches can share responses.
	msg := bytes.Clone(query)
	binary.BigEndian.PutUint16(msg, 0)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", stripURL(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned %s", res.Status)
	}
	if mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || mt != "application/dns-message" {
		return nil, errors.New("DoH upstream returned an unexpected content type")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDNSMessage+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) > maxDNSMessage {
		return nil, errors.New("DoH response exceeds the DNS message limit")
	}
	return body, nil
}

// stripURL keeps transport errors useful without echoing request details.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

type dotUpstream struct {
	spec upstreamSpec
	dial dialFunc
}

func (u *dotUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	raw, err := u.dial(ctx, "tcp", u.spec.hostPort)
	if err != nil {
		return nil, fmt.Errorf("DoT dial failed: %w", err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: u.spec.serverName, MinVersion: tls.VersionTLS12})
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("DoT handshake failed: %w", err)
	}

	// Use a fresh random ID on the wire; the forwarder restores the client ID.
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := rand.Read(msg[2:4]); err != nil {
		return nil, err
	}
	wireID := binary.BigEndian.Uint16(msg[2:4])
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("DoT write failed: %w", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("DoT read failed: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < dnsHeaderLen {
		return nil, errors.New("DoT response is too short")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("DoT read failed: %w", err)
	}
	if binary.BigEndian.Uint16(resp) != wireID {
		return nil, errors.New("DoT response ID mismatch")
	}
	return resp, nil
}
