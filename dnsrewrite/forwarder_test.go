package dnsrewrite

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream answers with reply(query) after an optional delay.
type fakeUpstream struct {
	delay time.Duration
	reply func(query []byte) ([]byte, error)
	calls atomic.Int32
}

func (u *fakeUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	u.calls.Add(1)
	if u.delay > 0 {
		select {
		case <-time.After(u.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return u.reply(query)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestForwarder(clock *fakeClock, ups ...upstream) *forwarder {
	f := &forwarder{upstreams: ups, timeout: 2 * time.Second, hedgeDelay: 50 * time.Millisecond, cache: newAnswerCache()}
	if clock != nil {
		f.cache.now = clock.now
	}
	return f
}

type queryOpts struct {
	id    uint16
	name  string
	qtype dnsmessage.Type
	do    bool
}

func buildQuery(t *testing.T, o queryOpts) []byte {
	t.Helper()
	if o.qtype == 0 {
		o.qtype = dnsmessage.TypeA
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: o.id, RecursionDesired: true})
	must(t, b.StartQuestions())
	must(t, b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(o.name), Type: o.qtype, Class: dnsmessage.ClassINET}))
	must(t, b.StartAdditionals())
	var rh dnsmessage.ResourceHeader
	must(t, rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, o.do))
	must(t, b.OPTResource(rh, dnsmessage.OPTResource{}))
	out, err := b.Finish()
	must(t, err)
	return out
}

// answerA replies to any query with one A record of the given TTL, echoing
// the question and its OPT record.
func answerA(t *testing.T, ttl uint32, a [4]byte) func([]byte) ([]byte, error) {
	return func(query []byte) ([]byte, error) {
		var q dnsmessage.Message
		must(t, q.Unpack(query))
		m := dnsmessage.Message{
			Header:      dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
			Questions:   q.Questions,
			Answers:     []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: a}}},
			Additionals: q.Additionals,
		}
		return m.Pack()
	}
}

func answerRCode(t *testing.T, rcode dnsmessage.RCode, soaTTL, soaMin uint32) func([]byte) ([]byte, error) {
	return func(query []byte) ([]byte, error) {
		var q dnsmessage.Message
		must(t, q.Unpack(query))
		m := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: rcode},
			Questions: q.Questions,
		}
		if soaTTL > 0 {
			m.Authorities = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: soaTTL},
				Body: &dnsmessage.SOAResource{
					NS: dnsmessage.MustNewName("ns.example.org."), MBox: dnsmessage.MustNewName("host.example.org."),
					Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: soaMin,
				},
			}}
		}
		return m.Pack()
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func unpack(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	must(t, m.Unpack(b))
	return m
}

func TestCacheServesAgedAnswerWithClientIDAndCase(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	up := &fakeUpstream{reply: answerA(t, 300, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(clock, up)

	if _, err := f.forward(context.Background(), buildQuery(t, queryOpts{id: 1, name: "www.example.org."})); err != nil {
		t.Fatal(err)
	}
	clock.advance(100 * time.Second)
	resp, err := f.forward(context.Background(), buildQuery(t, queryOpts{id: 2, name: "WWW.Example.ORG."}))
	if err != nil {
		t.Fatal(err)
	}
	if got := up.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (second query should hit the cache)", got)
	}
	m := unpack(t, resp)
	if m.ID != 2 {
		t.Errorf("ID = %d, want the client's 2", m.ID)
	}
	if got := m.Questions[0].Name.String(); got != "WWW.Example.ORG." {
		t.Errorf("question = %q, want the client's exact case", got)
	}
	if got := m.Answers[0].Header.TTL; got != 200 {
		t.Errorf("TTL = %d, want 300-100 = 200", got)
	}
}

func TestCacheServesStaleThenRefreshes(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	var addr atomic.Value
	addr.Store([4]byte{1, 1, 1, 1})
	up := &fakeUpstream{reply: func(q []byte) ([]byte, error) { return answerA(t, 60, addr.Load().([4]byte))(q) }}
	f := newTestForwarder(clock, up)
	q := buildQuery(t, queryOpts{id: 7, name: "app.example.org."})

	if _, err := f.forward(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	addr.Store([4]byte{2, 2, 2, 2})
	clock.advance(120 * time.Second) // expired, inside the stale window

	resp, err := f.forward(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	m := unpack(t, resp)
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{1, 1, 1, 1} {
		t.Errorf("stale answer = %v, want the cached 1.1.1.1", a)
	}
	if got := m.Answers[0].Header.TTL; got != cacheStaleTTL {
		t.Errorf("stale TTL = %d, want %d", got, cacheStaleTTL)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err = f.forward(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if unpack(t, resp).Answers[0].Body.(*dnsmessage.AResource).A == [4]byte{2, 2, 2, 2} {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh never replaced the stale entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := up.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 (one fill, one refresh)", got)
	}
}

func TestCacheDropsEntriesPastStaleWindow(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	up := &fakeUpstream{reply: answerA(t, 60, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(clock, up)
	q := buildQuery(t, queryOpts{name: "old.example.org."})
	if _, err := f.forward(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	clock.advance(60*time.Second + cacheStaleWindow + time.Second)
	resp, err := f.forward(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if got := up.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 (entry beyond stale window must be refetched)", got)
	}
	if got := unpack(t, resp).Answers[0].Header.TTL; got != 60 {
		t.Errorf("TTL = %d, want a fresh 60", got)
	}
}

func TestCacheNegativeAnswerUsesSOAMinimum(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	up := &fakeUpstream{reply: answerRCode(t, dnsmessage.RCodeNameError, 900, 60)}
	f := newTestForwarder(clock, up)
	q := buildQuery(t, queryOpts{name: "nope.example.org."})
	for range 2 {
		if _, err := f.forward(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		clock.advance(30 * time.Second)
	}
	if got := up.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 within the 60s negative TTL", got)
	}
	resp, _ := f.forward(context.Background(), q) // at 60s: stale
	if got := unpack(t, resp).Authorities[0].Header.TTL; got != cacheStaleTTL {
		t.Errorf("stale SOA TTL = %d, want %d", got, cacheStaleTTL)
	}
}

func TestCacheSkipsUncacheableAnswers(t *testing.T) {
	cases := map[string]func([]byte) ([]byte, error){
		"servfail":        answerRCode(t, dnsmessage.RCodeServerFailure, 0, 0),
		"zero ttl":        answerA(t, 0, [4]byte{1, 2, 3, 4}),
		"nxdomain no soa": answerRCode(t, dnsmessage.RCodeNameError, 0, 0),
		"nodata zero soa": answerRCode(t, dnsmessage.RCodeSuccess, 300, 0),
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			up := &fakeUpstream{reply: reply}
			f := newTestForwarder(nil, up)
			q := buildQuery(t, queryOpts{name: "x.example.org."})
			for range 2 {
				if _, err := f.forward(context.Background(), q); err != nil {
					t.Fatal(err)
				}
			}
			if got := up.calls.Load(); got != 2 {
				t.Errorf("upstream calls = %d, want 2 (answer must not be cached)", got)
			}
		})
	}
}

func TestCacheKeySeparatesDNSSECOK(t *testing.T) {
	up := &fakeUpstream{reply: answerA(t, 300, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(nil, up)
	for _, do := range []bool{false, true} {
		if _, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "d.example.org.", do: do})); err != nil {
			t.Fatal(err)
		}
	}
	if got := up.calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (DO=0 and DO=1 are distinct)", got)
	}
	resp, _ := f.forward(context.Background(), buildQuery(t, queryOpts{name: "d.example.org.", do: true}))
	m := unpack(t, resp)
	for _, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT && !rr.Header.DNSSECAllowed() {
			t.Error("cached answer lost the OPT DO flag (OPT TTL must not be aged)")
		}
	}
}

func TestHedgeQueriesNextUpstreamWhenFirstIsSlow(t *testing.T) {
	slow := &fakeUpstream{delay: 5 * time.Second, reply: answerA(t, 60, [4]byte{9, 9, 9, 9})}
	fast := &fakeUpstream{reply: answerA(t, 60, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(nil, slow, fast)
	start := time.Now()
	resp, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "h.example.org."}))
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("took %v; the hedge should answer after ~hedgeDelay", el)
	}
	if a := unpack(t, resp).Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{1, 2, 3, 4} {
		t.Errorf("answer = %v, want the fast upstream's", a)
	}
}

func TestFailoverIsImmediateOnError(t *testing.T) {
	broken := &fakeUpstream{reply: func([]byte) ([]byte, error) { return nil, errors.New("boom") }}
	good := &fakeUpstream{reply: answerA(t, 60, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(nil, broken, good)
	f.hedgeDelay = time.Hour // only an error may trigger the second upstream
	if _, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "f.example.org."})); err != nil {
		t.Fatal(err)
	}
	if good.calls.Load() != 1 {
		t.Error("second upstream was not tried after the first failed")
	}
}

func TestFirstUpstreamWinsWhenFast(t *testing.T) {
	first := &fakeUpstream{reply: answerA(t, 60, [4]byte{1, 1, 1, 1})}
	second := &fakeUpstream{reply: answerA(t, 60, [4]byte{2, 2, 2, 2})}
	f := newTestForwarder(nil, first, second)
	if _, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "w.example.org."})); err != nil {
		t.Fatal(err)
	}
	if second.calls.Load() != 0 {
		t.Error("second upstream was queried although the first answered within hedgeDelay")
	}
}

func TestAllUpstreamsFail(t *testing.T) {
	fail := func([]byte) ([]byte, error) { return nil, errors.New("down") }
	f := newTestForwarder(nil, &fakeUpstream{reply: fail}, &fakeUpstream{reply: fail})
	if _, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "z.example.org."})); err == nil {
		t.Fatal("want an error when every upstream fails")
	}
}

func TestMismatchedAnswerIsRejectedAndNotCached(t *testing.T) {
	wrong := &fakeUpstream{reply: func(q []byte) ([]byte, error) {
		other := buildQuery(t, queryOpts{id: binary.BigEndian.Uint16(q), name: "other.example.org."})
		return answerA(t, 300, [4]byte{6, 6, 6, 6})(other)
	}}
	right := &fakeUpstream{delay: 10 * time.Millisecond, reply: answerA(t, 300, [4]byte{1, 2, 3, 4})}
	f := newTestForwarder(nil, wrong, right)
	resp, err := f.forward(context.Background(), buildQuery(t, queryOpts{name: "m.example.org."}))
	if err != nil {
		t.Fatal(err)
	}
	if a := unpack(t, resp).Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{1, 2, 3, 4} {
		t.Errorf("answer = %v, want the valid upstream's", a)
	}
}
