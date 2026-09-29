package harness

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

var gate = netip.MustParseAddr("127.0.10.5")

const gated = `; hark: root-hints = 127.0.10.1
; hark: qname-minimisation = no

SCENARIO_BEGIN a gated authority settles a name two clients wait on
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR NOERROR
    SECTION QUESTION
      example.com. IN A
    SECTION AUTHORITY
      example.com. 86400 IN NS ns1.example.com.
    SECTION ADDITIONAL
      ns1.example.com. 86400 IN A 127.0.10.5
  ENTRY_END
RANGE_END
SCENARIO_END
`

func serveGate(t *testing.T, port uint16) (open chan struct{}) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(gate, port)))
	if err != nil {
		t.Fatal(err)
	}
	open = make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() { c.Close(); <-done })
	go func() {
		defer close(done)
		select {
		case <-open:
		case <-t.Context().Done():
			return
		}
		buf := make([]byte, 4096)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := &dns.Msg{Data: buf[:n]}
			if q.Unpack() != nil || len(q.Question) == 0 {
				continue
			}
			a, _ := dns.New(q.Question[0].Header().Name + " 300 IN A 192.0.2.7")
			m := replyTo(q)
			m.Authoritative, m.Answer = true, []dns.RR{a}
			if m.Pack() == nil {
				c.WriteToUDPAddrPort(m.Data, from)
			}
		}
	}()
	return open
}

func TestAJoinerWaitsAsLongAsTheFirst(t *testing.T) {
	t.Parallel()
	resp, h := launchText(t, gated, nil)
	open := serveGate(t, resp.port)

	answered := func(network string) <-chan time.Time {
		at := make(chan time.Time, 1)
		go func() {
			if _, err := ask(t.Context(), network, h.addr, "a.example.com.", 3*time.Second); err != nil {
				t.Errorf("%s: %v", network, err)
			}
			at <- time.Now()
		}()
		return at
	}
	first := answered("udp")
	time.Sleep(time.Second)
	joiner := answered("udp")
	unspoofable := answered("tcp")
	time.Sleep(100 * time.Millisecond)
	close(open)
	opened := time.Now()

	if d := (<-first).Sub(opened); d >= 500*time.Millisecond {
		t.Errorf("first asker answered %v after the gate opened", d)
	}
	if d := (<-unspoofable).Sub(opened); d >= 500*time.Millisecond {
		t.Errorf("TCP asker answered %v after the gate opened", d)
	}
	if d := (<-joiner).Sub(opened); d <= 500*time.Millisecond || d >= 1800*time.Millisecond {
		t.Errorf("UDP joiner answered %v after the gate opened, want 0.5 to 1.8 s", d)
	}

	t0 := time.Now()
	wantRcode(t, h.addr, "a.example.com.", dns.RcodeSuccess, time.Second)
	if d := time.Since(t0); d >= 500*time.Millisecond {
		t.Errorf("the settled name took %v", d)
	}
}
