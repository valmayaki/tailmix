package dnsrewrite

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	cacheMaxEntries = 4096
	// cacheMaxTTL bounds how long an upstream answer is served as fresh.
	cacheMaxTTL = time.Hour
	// cacheStaleWindow is how long past expiry an answer may still be served
	// while it is refreshed in the background (RFC 8767 serve-stale).
	cacheStaleWindow = time.Hour
	// cacheStaleTTL is the TTL clients see on a stale answer (RFC 8767 §4).
	cacheStaleTTL = 30
)

// cacheKey identifies an upstream answer. DO and CD change what the upstream
// returns, so they are part of the key.
type cacheKey struct {
	name  string // lower-case, as sent
	qtype dnsmessage.Type
	class dnsmessage.Class
	do    bool
	cd    bool
}

type cacheEntry struct {
	msg     dnsmessage.Message
	stored  time.Time
	expires time.Time
}

// answerCache holds raw upstream answers, before any profile rewrite, so the
// rewrite always runs against the current peer snapshot.
type answerCache struct {
	mu         sync.Mutex
	entries    map[cacheKey]*cacheEntry
	refreshing map[cacheKey]bool
	now        func() time.Time
}

func newAnswerCache() *answerCache {
	return &answerCache{
		entries:    map[cacheKey]*cacheEntry{},
		refreshing: map[cacheKey]bool{},
		now:        time.Now,
	}
}

// keyFor returns the cache key for a single-question query, or false when the
// query should bypass the cache.
func keyFor(query []byte) (cacheKey, []dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response || h.OpCode != 0 {
		return cacheKey{}, nil, false
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return cacheKey{}, nil, false
	}
	k := cacheKey{
		name:  strings.ToLower(qs[0].Name.String()),
		qtype: qs[0].Type,
		class: qs[0].Class,
		cd:    h.CheckingDisabled,
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return cacheKey{}, nil, false
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			k.do = rh.DNSSECAllowed()
		}
		if p.SkipAdditional() != nil {
			break
		}
	}
	return k, qs, true
}

// lookup returns a cached answer re-packed for this query with TTLs aged, and
// whether it is stale (the caller should refresh it).
func (c *answerCache) lookup(k cacheKey, questions []dnsmessage.Question) (resp []byte, stale, ok bool) {
	c.mu.Lock()
	e, found := c.entries[k]
	now := c.now()
	if found && now.After(e.expires.Add(cacheStaleWindow)) {
		delete(c.entries, k)
		found = false
	}
	if !found {
		c.mu.Unlock()
		return nil, false, false
	}
	m := e.msg // shallow copy; the record slices are cloned by agedMessage
	stale = !now.Before(e.expires)
	age := now.Sub(e.stored)
	c.mu.Unlock()

	out := agedMessage(m, age, stale)
	// Echo the client's question exactly, including name case.
	out.Questions = questions
	b, err := out.Pack()
	if err != nil || len(b) > maxDNSMessage {
		return nil, false, false
	}
	return b, stale, true
}

// store caches a validated upstream answer when its TTLs allow it.
func (c *answerCache) store(k cacheKey, resp []byte) {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return
	}
	ttl, ok := cacheTTL(&m)
	if !ok {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[k]; !exists && len(c.entries) >= cacheMaxEntries {
		c.evictLocked(now)
	}
	c.entries[k] = &cacheEntry{msg: m, stored: now, expires: now.Add(ttl)}
}

// beginRefresh reports whether the caller should refresh k; only one refresh
// per key runs at a time.
func (c *answerCache) beginRefresh(k cacheKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing[k] {
		return false
	}
	c.refreshing[k] = true
	return true
}

func (c *answerCache) endRefresh(k cacheKey) {
	c.mu.Lock()
	delete(c.refreshing, k)
	c.mu.Unlock()
}

// evictLocked drops entries past their stale window, then arbitrary entries,
// until there is room for one more.
func (c *answerCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if now.After(e.expires.Add(cacheStaleWindow)) {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) < cacheMaxEntries {
			break
		}
		delete(c.entries, k)
	}
}

// cacheTTL picks the cache lifetime: the lowest answer TTL for positive
// answers, or the SOA-derived negative TTL (RFC 2308) for NXDOMAIN and NODATA.
// Truncated, failed, or zero-TTL answers are not cached.
func cacheTTL(m *dnsmessage.Message) (time.Duration, bool) {
	if m.Truncated || len(m.Questions) != 1 {
		return 0, false
	}
	var ttl uint32
	have := false
	lower := func(v uint32) {
		if !have || v < ttl {
			ttl, have = v, true
		}
	}
	switch {
	case m.RCode == dnsmessage.RCodeSuccess && len(m.Answers) > 0:
		for _, rr := range m.Answers {
			lower(rr.Header.TTL)
		}
	case m.RCode == dnsmessage.RCodeSuccess || m.RCode == dnsmessage.RCodeNameError:
		for _, rr := range m.Authorities {
			if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
				lower(min(rr.Header.TTL, soa.MinTTL))
			}
		}
	}
	if !have || ttl == 0 {
		return 0, false
	}
	return min(time.Duration(ttl)*time.Second, cacheMaxTTL), true
}

// agedMessage returns m with every record TTL reduced by age, or set to
// cacheStaleTTL when stale. The OPT pseudo-record's TTL carries flags, not a
// lifetime, and is left alone.
func agedMessage(m dnsmessage.Message, age time.Duration, stale bool) dnsmessage.Message {
	elapsed := uint32(min(age/time.Second, 1<<31))
	adjust := func(in []dnsmessage.Resource) []dnsmessage.Resource {
		out := make([]dnsmessage.Resource, len(in))
		copy(out, in)
		for i := range out {
			h := &out[i].Header
			switch {
			case h.Type == dnsmessage.TypeOPT:
			case stale:
				h.TTL = cacheStaleTTL
			case h.TTL > elapsed:
				h.TTL -= elapsed
			default:
				h.TTL = 1
			}
		}
		return out
	}
	m.Answers = adjust(m.Answers)
	m.Authorities = adjust(m.Authorities)
	m.Additionals = adjust(m.Additionals)
	return m
}
