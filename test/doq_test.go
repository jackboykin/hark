package harness

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
)

type doqServer struct {
	l     *quic.Listener
	port  uint16
	shook atomic.Int64
	ended atomic.Int64
	mu    sync.Mutex
	alpn  []string
	asked []*dns.Msg
}

func startDoq(t *testing.T, serve func(s *doqServer, st *quic.Stream, q *dns.Msg)) *doqServer {
	t.Helper()
	s := &doqServer{}
	cfg := &tls.Config{Certificates: []tls.Certificate{self(t)}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}
	l, err := quic.ListenAddr("127.0.10.1:0", cfg, &quic.Config{MaxIncomingStreams: 1000, MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.l = l
	s.port = uint16(l.Addr().(*net.UDPAddr).Port)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			s.shook.Add(1)
			s.mu.Lock()
			s.alpn = append(s.alpn, c.ConnectionState().TLS.NegotiatedProtocol)
			s.mu.Unlock()
			go func() {
				defer s.ended.Add(1)
				for {
					st, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						q, err := readDoq(st)
						if err != nil {
							return
						}
						s.mu.Lock()
						s.asked = append(s.asked, q)
						s.mu.Unlock()
						serve(s, st, q)
					}()
				}
			}()
		}
	}()
	return s
}

func readDoq(st *quic.Stream) (*dns.Msg, error) {
	b, err := io.ReadAll(st)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 || int(b[0])<<8|int(b[1]) != len(b)-2 {
		return nil, fmt.Errorf("a stream of %d bytes", len(b))
	}
	q := &dns.Msg{Data: b[2:]}
	if err := q.Unpack(); err != nil {
		return nil, err
	}
	return q, nil
}

func doqAnswering(answers int) func(*doqServer, *quic.Stream, *dns.Msg) {
	return func(_ *doqServer, st *quic.Stream, q *dns.Msg) {
		st.Write(dotReply(q, answers))
		st.Close()
	}
}

func launchDoq(t *testing.T, s *doqServer, names ...string) *hark {
	t.Helper()
	_, h := launchText(t, dotScenario(names...), func(c *config) { c.dotPort = s.port })
	return h
}

func TestDoqOnceAServerTakesIt(t *testing.T) {
	t.Parallel()
	s := startDoq(t, doqAnswering(1))
	h := launchDoq(t, s, "a.example.com.", "b.example.com.", "c.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	waitFor(t, "a handshake", func() bool { return s.shook.Load() == 1 })
	waitFor(t, "the probe letting go", func() bool { return s.ended.Load() == 1 })
	wantAnswer(t, h, "b.example.com.", dotAnswer)
	wantAnswer(t, h, "c.example.com.", dotAnswer)
	if s.shook.Load() != 2 {
		t.Errorf("%d handshakes, want the probe's and the questions'", s.shook.Load())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.alpn {
		if p != "doq" {
			t.Errorf("alpn %q", p)
		}
	}
	for _, q := range s.asked {
		// RFC 9250 §4.2.1: id 0; RFC 7830 §4: a padding option asks for a padded reply.
		padded := false
		for _, o := range q.Pseudo {
			if _, ok := o.(*dns.PADDING); ok {
				padded = true
			}
		}
		if q.ID != 0 || !padded {
			t.Errorf("query id %d, padding asked %v", q.ID, padded)
		}
	}
}

func TestDoqAReplyAcrossPackets(t *testing.T) {
	t.Parallel()
	s := startDoq(t, doqAnswering(80))
	h := launchDoq(t, s, "a.example.com.", "b.example.com.")
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	waitFor(t, "the probe letting go", func() bool { return s.ended.Load() == 1 })
	r, err := ask(t.Context(), "tcp", h.addr, "b.example.com.", 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 80 {
		t.Fatalf("%d answers over DoQ, want 80:\n%v", len(r.Answer), r)
	}
}

func TestDoqQuestionsShareOneConnection(t *testing.T) {
	t.Parallel()
	const n = 200
	names := []string{"a.example.com."}
	for i := range n {
		names = append(names, fmt.Sprintf("q%d.example.com.", i))
	}
	s := startDoq(t, doqAnswering(1))
	h := launchDoq(t, s, names...)
	wantAnswer(t, h, names[0], plainAnswer)
	waitFor(t, "the probe letting go", func() bool { return s.ended.Load() == 1 })
	wantAnswer(t, h, names[1], dotAnswer)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, name := range names[2:] {
		wg.Go(func() {
			r, err := ask(t.Context(), "udp", h.addr, name, 4*time.Second)
			if err == nil && (len(r.Answer) == 0 || r.Answer[0].(*dns.A).A.Addr.String() != dotAnswer) {
				err = fmt.Errorf("%s: %v", name, r)
			}
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if s.shook.Load() != 2 {
		t.Errorf("%d handshakes for one burst", s.shook.Load())
	}
}

func TestDoqSilenceGoesPlainAndDamps(t *testing.T) {
	t.Parallel()
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.10.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var heard atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			heard.Add(1)
		}
	}()
	_, h := launchText(t, dotScenario("a.example.com.", "b.example.com.", "c.example.com."), func(c *config) { c.dotPort = uint16(pc.LocalAddr().(*net.UDPAddr).Port) })
	wantAnswer(t, h, "a.example.com.", plainAnswer)
	waitFor(t, "an Initial", func() bool { return heard.Load() > 0 })
	// Past its 4 s dial, the silence holds the port shut a day (RFC 9539 §4.3).
	time.Sleep(4200 * time.Millisecond)
	before := heard.Load()
	t0 := time.Now()
	wantAnswer(t, h, "b.example.com.", plainAnswer)
	if d := time.Since(t0); d > 100*time.Millisecond {
		t.Errorf("a damped server cost %v", d)
	}
	time.Sleep(100 * time.Millisecond)
	if heard.Load() != before {
		t.Errorf("%d datagrams to a damped server", heard.Load()-before)
	}
}
