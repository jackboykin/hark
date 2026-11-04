package harness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// An authority whose plain answers and DoT answers differ, which no real one's
// may (RFC 9539 §3), so a reply says how it came.
const (
	plainAnswer = "192.0.2.1"
	dotAnswer   = "192.0.2.2"
)

func dotScenario(names ...string) string {
	var b strings.Builder
	b.WriteString("; hark: root-hints = 127.0.10.1\n; hark: qname-minimisation = no\n\nSCENARIO_BEGIN dot\nRANGE_BEGIN 0 100\n  ADDRESS 127.0.10.1\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  ENTRY_BEGIN\n    MATCH opcode qname qtype\n    ADJUST copy_id copy_query\n    REPLY QR AA NOERROR\n    SECTION QUESTION\n      %s IN A\n    SECTION ANSWER\n      %s 300 IN A %s\n  ENTRY_END\n", n, n, plainAnswer)
	}
	b.WriteString("RANGE_END\nSCENARIO_END\n")
	return b.String()
}

type dotServer struct {
	l     net.Listener
	conns atomic.Int64
	// Past a handshake, hark has heard the server's Finished and said its own.
	shook atomic.Int64
	// Past a close, hark has heard it and let go.
	ended   atomic.Int64
	queries atomic.Int64
	mu      sync.Mutex
	sni     []string
	alpn    []string
	sizes   []int
	stall   func() bool
}

func self(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startDot(t *testing.T, tweak func(*dotServer, *tls.Config), serve func(s *dotServer, c net.Conn)) *dotServer {
	t.Helper()
	s := &dotServer{}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{self(t)},
		NextProtos:   []string{"dot"},
		MinVersion:   tls.VersionTLS13,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.sni = append(s.sni, h.ServerName)
			s.alpn = append(s.alpn, h.SupportedProtos...)
			return nil, nil
		},
	}
	if tweak != nil {
		tweak(s, cfg)
	}
	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.10.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.l = inner
	t.Cleanup(func() { inner.Close() })
	go func() {
		for {
			c, err := inner.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go func() {
				defer c.Close()
				if s.stall != nil && s.stall() {
					return
				}
				tc := tls.Server(c, cfg)
				if tc.HandshakeContext(context.Background()) != nil {
					return
				}
				s.shook.Add(1)
				serve(s, tc)
				tc.CloseWrite()
				io.Copy(io.Discard, tc)
				s.ended.Add(1)
			}()
		}
	}()
	return s
}

func (s *dotServer) port() uint16 {
	return uint16(s.l.Addr().(*net.TCPAddr).Port)
}

func (s *dotServer) read(c net.Conn) (*dns.Msg, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.sizes = append(s.sizes, len(b))
	s.mu.Unlock()
	s.queries.Add(1)
	q := &dns.Msg{Data: b}
	if err := q.Unpack(); err != nil {
		return nil, err
	}
	return q, nil
}

func dotReply(q *dns.Msg, answers int) []byte {
	m := replyTo(q)
	m.Authoritative = true
	name := q.Question[0].Header().Name
	for i := range answers {
		rr, err := dns.New(fmt.Sprintf("%s 300 IN A %s", name, dotAnswerN(i)))
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	b, err := frame(m)
	if err != nil {
		panic(err)
	}
	return b
}

func dotAnswerN(i int) string {
	if i == 0 {
		return dotAnswer
	}
	return fmt.Sprintf("192.0.2.%d", 2+i)
}

func answering(s *dotServer, c net.Conn) {
	for {
		q, err := s.read(c)
		if err != nil {
			return
		}
		if _, err := c.Write(dotReply(q, 1)); err != nil {
			return
		}
	}
}

func launchDot(t *testing.T, s *dotServer, names ...string) *hark {
	t.Helper()
	_, h := launchText(t, dotScenario(names...), func(c *config) { c.dotPort = s.port() })
	return h
}

func (s *dotServer) waitShook(t *testing.T, n int64) {
	t.Helper()
	waitFor(t, "a handshake", func() bool { return s.shook.Load() >= n })
}

func wantAnswer(t *testing.T, h *hark, name, want string) {
	t.Helper()
	r, err := ask(t.Context(), "udp", h.addr, name, 4*time.Second)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(r.Answer) == 0 || !strings.HasSuffix(r.Answer[0].String(), want) {
		t.Fatalf("%s: want %s, got:\n%v", name, want, r)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 400 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

func TestDotOnceAServerTakesIt(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, answering)
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	wantAnswer(t, h, "b.example.com.", dotAnswer)
	if s.conns.Load() != 1 {
		t.Errorf("%d dials, want the one", s.conns.Load())
	}
	// §4.3: three days from its last reply, a server is unknown again.
	if err := advanceClock(t.Context(), h.addr, 3*24*3600); err != nil {
		t.Fatal(err)
	}
	wantAnswer(t, h, "c.example.com.", plainAnswer)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sni) == 0 || strings.Join(s.sni, "") != "" || strings.Join(s.alpn, "") != strings.Repeat("dot", len(s.sni)) {
		t.Errorf("hellos: sni %q, alpn %q", s.sni, s.alpn)
	}
	if len(s.sizes) != 1 || s.sizes[0]%128 != 0 {
		t.Errorf("query sizes %v, want one multiple of 128", s.sizes)
	}
}

func TestDotHangingUpOnAQueryGoesPlainAndDamps(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, func(s *dotServer, c net.Conn) { s.read(c) })
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	wantAnswer(t, h, "b.example.com.", plainAnswer)
	if s.queries.Load() != 1 {
		t.Errorf("%d queries over DoT, want the one it hung up on", s.queries.Load())
	}
	// Past the moment any close holds it plain: a day, for one that never answered.
	if err := advanceClock(t.Context(), h.addr, 3600); err != nil {
		t.Fatal(err)
	}
	wantAnswer(t, h, "c.example.com.", plainAnswer)
	time.Sleep(50 * time.Millisecond)
	if s.conns.Load() != 1 {
		t.Errorf("%d dials: damping should have stopped a second", s.conns.Load())
	}
}

func TestDotSilenceGoesPlainAndDamps(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		s.read(c)
		<-release
	})
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	t0 := time.Now()
	wantAnswer(t, h, "b.example.com.", plainAnswer)
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("silence cost %v", d)
	}
	t0 = time.Now()
	wantAnswer(t, h, "c.example.com.", plainAnswer)
	if d := time.Since(t0); d > 100*time.Millisecond {
		t.Errorf("a damped server cost %v", d)
	}
}

func TestDotAPortThatSpeaksNonsenseIsDamped(t *testing.T) {
	t.Parallel()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.10.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var dials atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			c.Write([]byte("220 smtp.example.com ESMTP\r\n"))
			defer c.Close()
		}
	}()
	_, h := launchText(t, dotScenario("a.example.com.", "b.example.com.", "c.example.com."), func(c *config) { c.dotPort = uint16(l.Addr().(*net.TCPAddr).Port) })
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	waitFor(t, "a dial", func() bool { return dials.Load() == 1 })
	// Past its 4 s dial, the failure itself holds the port shut, a day (§4.3).
	if err := advanceClock(t.Context(), h.addr, 3600); err != nil {
		t.Fatal(err)
	}
	wantAnswer(t, h, "b.example.com.", plainAnswer)
	time.Sleep(50 * time.Millisecond)
	if dials.Load() != 1 {
		t.Errorf("%d dials an hour on, want the one", dials.Load())
	}
	if err := advanceClock(t.Context(), h.addr, 24*3600); err != nil {
		t.Fatal(err)
	}
	wantAnswer(t, h, "c.example.com.", plainAnswer)
	waitFor(t, "a dial once the damping ended", func() bool { return dials.Load() == 2 })
}

func TestDotAnIdleCloseJustDialsAgain(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		if q, err := s.read(c); err == nil {
			c.Write(dotReply(q, 1))
		}
	})
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.", "d.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	wantAnswer(t, h, "b.example.com.", dotAnswer)
	waitFor(t, "the close", func() bool { return s.ended.Load() == 1 })
	wantAnswer(t, h, "c.example.com.", dotAnswer)
	waitFor(t, "the close", func() bool { return s.ended.Load() == 2 })
	wantAnswer(t, h, "d.example.com.", dotAnswer)
	if s.conns.Load() != 3 {
		t.Errorf("%d dials, want one per session", s.conns.Load())
	}
}

func TestDotAStalledDialDoesNotHoldQuestions(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	// The first session answers once and closes; the port then takes
	// connections and says nothing.
	s := startDot(t, func(s *dotServer, _ *tls.Config) {
		s.stall = func() bool {
			if s.conns.Load() == 1 {
				return false
			}
			<-release
			return true
		}
	}, func(s *dotServer, c net.Conn) {
		if q, err := s.read(c); err == nil {
			c.Write(dotReply(q, 1))
		}
	})
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	wantAnswer(t, h, "b.example.com.", dotAnswer)
	waitFor(t, "the close", func() bool { return s.ended.Load() == 1 })
	t0 := time.Now()
	wantAnswer(t, h, "c.example.com.", plainAnswer)
	if d := time.Since(t0); d > 1500*time.Millisecond {
		t.Errorf("a stalled dial held a question %v", d)
	}
}

func TestDotALostQueryLeavesALiveSession(t *testing.T) {
	t.Parallel()
	var asked atomic.Int64
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		for {
			q, err := s.read(c)
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.ToLower(q.Question[0].Header().Name), "lost.") {
				asked.Add(1)
				continue
			}
			if _, err := c.Write(dotReply(q, 1)); err != nil {
				return
			}
		}
	})
	h := launchDot(t, s, "a.example.com.", "lost.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	lost := make(chan struct{})
	go func() {
		ask(t.Context(), "udp", h.addr, "lost.example.com.", 4*time.Second)
		close(lost)
	}()
	for i := 0; ; i++ {
		select {
		case <-lost:
			if s.conns.Load() != 1 {
				t.Errorf("%d dials: the session went on answering, so it should have stayed", s.conns.Load())
			}
			// A timeout, so the walk's one retry; not asked again without end.
			if asked.Load() > 2 {
				t.Errorf("the lost question was asked %d times", asked.Load())
			}
			return
		case <-time.After(20 * time.Millisecond):
			wantAnswer(t, h, fmt.Sprintf("k%d.example.com.", i), dotAnswer)
		}
	}
}

// §4.6.7: what a close leaves pending goes plain, not onto another dial, or a
// server that answers once a connection serves one query a handshake.
func TestDotAClosePendingQueriesGoPlain(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		q, err := s.read(c)
		if err != nil {
			return
		}
		time.Sleep(30 * time.Millisecond)
		c.Write(dotReply(q, 1))
	})
	names := []string{"a.example.com."}
	for i := range 8 {
		names = append(names, fmt.Sprintf("q%d.example.com.", i))
	}
	h := launchDot(t, s, names...)
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	var wg sync.WaitGroup
	var answered atomic.Int64
	for _, n := range names[1:] {
		wg.Go(func() {
			if r, err := ask(t.Context(), "udp", h.addr, n, 2*time.Second); err == nil && len(r.Answer) > 0 {
				answered.Add(1)
			}
		})
	}
	wg.Wait()
	if answered.Load() != 8 {
		t.Errorf("%d of 8 answered", answered.Load())
	}
	if s.conns.Load() != 1 {
		t.Errorf("%d dials: a close with queries pending should not dial again at once", s.conns.Load())
	}
}

// A reply still queued when the same read leaves part of the next behind.
func TestDotAReplyOutlivesAPartialOneBehindIt(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		first, err := s.read(c)
		if err != nil {
			return
		}
		second, err := s.read(c)
		if err != nil {
			return
		}
		a, b := dotReply(first, 1), dotReply(second, 1)
		if _, err := c.Write(append(a[:len(a):len(a)], b[:5]...)); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
		c.Write(b[5:])
		answering(s, c)
	})
	h := launchDot(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	var wg sync.WaitGroup
	for _, n := range []string{"b.example.com.", "c.example.com."} {
		wg.Go(func() { wantAnswer(t, h, n, dotAnswer) })
	}
	wg.Wait()
	// A reply spoiled in the buffer reads as a mismatch and earns a retry.
	if s.conns.Load() != 1 || s.queries.Load() != 2 {
		t.Errorf("%d dials, %d queries: want one session carrying both once", s.conns.Load(), s.queries.Load())
	}
}

func TestDotACertificateRequestIsAnsweredWithNone(t *testing.T) {
	t.Parallel()
	s := startDot(t, func(_ *dotServer, c *tls.Config) { c.ClientAuth = tls.RequestClientCert }, answering)
	h := launchDot(t, s, "a.example.com.", "b.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	wantAnswer(t, h, "b.example.com.", dotAnswer)
}

func TestDotABigReplyAcrossRecords(t *testing.T) {
	t.Parallel()
	s := startDot(t, nil, func(s *dotServer, c net.Conn) {
		for {
			q, err := s.read(c)
			if err != nil {
				return
			}
			b := dotReply(q, 100)
			if len(b) < 1400 {
				panic("not big")
			}
			for _, part := range [][]byte{b[:1], b[1:700], b[700:]} {
				if _, err := c.Write(part); err != nil {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	})
	h := launchDot(t, s, "a.example.com.", "b.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	s.waitShook(t, 1)
	r, err := ask(t.Context(), "tcp", h.addr, "b.example.com.", 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 100 {
		t.Fatalf("want all 100 records, got:\n%v", r)
	}
}
