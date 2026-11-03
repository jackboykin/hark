package harness

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

const twoSilent = `; hark: root-hints = 127.0.10.1
; hark: qname-minimisation = no

SCENARIO_BEGIN two silent authorities outlast a stub
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
      example.com. 86400 IN NS ns2.example.com.
    SECTION ADDITIONAL
      ns1.example.com. 86400 IN A 127.0.10.3
      ns2.example.com. 86400 IN A 127.0.10.4
  ENTRY_END
RANGE_END
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.3
  ENTRY_BEGIN
    MATCH opcode
    ADJUST drop
    REPLY QR AA NOERROR
    SECTION QUESTION
      example.com. IN A
  ENTRY_END
RANGE_END
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.4
  ENTRY_BEGIN
    MATCH opcode
    ADJUST drop
    REPLY QR AA NOERROR
    SECTION QUESTION
      example.com. IN A
  ENTRY_END
RANGE_END
SCENARIO_END
`

func TestLateUDPIsSilentAndTCPIsAnswered(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, twoSilent, nil)
	udp := make(chan error, 1)
	go func() {
		_, err := ask(t.Context(), "udp", h.addr, "b.example.com.", 4500*time.Millisecond)
		udp <- err
	}()
	t0 := time.Now()
	r, err := ask(t.Context(), "tcp", h.addr, "a.example.com.", 4500*time.Millisecond)
	took := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeServerFailure {
		t.Errorf("TCP: want SERVFAIL, got:\n%v", r)
	}
	if took <= 2*time.Second || took >= 4*time.Second {
		t.Fatalf("TCP answered in %v: the test needs a reply due past 2 s and inside the UDP wait", took)
	}
	if err := <-udp; !timedOut(err) {
		t.Errorf("UDP: want no reply, got %v", err)
	}

	t0 = time.Now()
	wantRcode(t, h.addr, "b.example.com.", dns.RcodeServerFailure, 2*time.Second)
	if d := time.Since(t0); d >= 500*time.Millisecond {
		t.Errorf("the remembered failure took %v", d)
	}
}

func TestTheQueryLimitKeepsTheAnswersOwed(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, twoSilent, func(c *config) { c.tcpQueries = 2 })
	c := dial(t, h)
	send(t, c, append(framed(t, "a.example.com.", 1), framed(t, "b.example.com.", 2)...))
	time.Sleep(100 * time.Millisecond)
	send(t, c, framed(t, "c.example.com.", 3))
	if got := ids(replies(t, c, 3)); !slices.Equal(got, []uint16{1, 2}) {
		t.Fatalf("replies to %v, want 1 and 2", got)
	}
}

func TestAResetTCPClientLeavesTheLoopFree(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, twoSilent, func(c *config) { c.serveStaleTTL = 60 })
	c := dial(t, h)
	send(t, c, framed(t, "a.example.com.", 1))
	time.Sleep(200 * time.Millisecond)
	if err := c.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	c.Close()
	time.Sleep(2200 * time.Millisecond)
	wantRcode(t, h.addr, "after.invalid.", dns.RcodeNameError, time.Second)
}

// Each hop takes most of an untimed server's 400 ms, so the walk outlasts a
// stub's 1.8 s patience.
const (
	staleName = "a.b.c.d.e.f.g.example.com."
	staleHops = 8
)

const staleWalk = `; hark: root-hints = 127.0.10.1
; hark: qname-minimisation = no

SCENARIO_BEGIN a refresh longer than a stub's patience
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR NOERROR
    SECTION QUESTION
      example.com. IN A
    SECTION AUTHORITY
      example.com. 86400 IN NS ns.example.com.
    SECTION ADDITIONAL
      ns.example.com. 86400 IN A 127.0.10.20
  ENTRY_END
RANGE_END
SCENARIO_END
`

func serveStaleWalk(t *testing.T, port uint16) {
	t.Helper()
	labels := strings.Split(strings.TrimSuffix(staleName, "."), ".")
	var answered atomic.Bool
	for hop := range staleHops {
		at := netip.AddrFrom4([4]byte{127, 0, 10, byte(20 + hop)})
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(at, port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			buf := make([]byte, 4096)
			for {
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				q := &dns.Msg{Data: slices.Clone(buf[:n])}
				if q.Unpack() != nil || len(q.Question) == 0 {
					continue
				}
				m := replyTo(q)
				rr := func(text string) dns.RR {
					r, err := dns.New(text)
					if err != nil {
						panic(err)
					}
					return r
				}
				delay := 350 * time.Millisecond
				switch {
				case hop == 0 && !answered.Swap(true):
					delay = 0
					m.Authoritative = true
					m.Answer = []dns.RR{rr(staleName + " 1 IN A 192.0.2.1")}
				case hop == staleHops-1:
					m.Authoritative = true
					m.Answer = []dns.RR{rr(staleName + " 300 IN A 192.0.2.2")}
				default:
					if hop == 0 {
						delay = 0
					}
					cut := strings.Join(labels[len(labels)-hop-3:], ".") + "."
					m.Ns = []dns.RR{rr(cut + " 86400 IN NS ns." + cut)}
					m.Extra = []dns.RR{rr(fmt.Sprintf("ns.%s 86400 IN A 127.0.10.%d", cut, 21+hop))}
				}
				time.AfterFunc(delay, func() {
					if m.Pack() == nil {
						c.WriteToUDPAddrPort(m.Data, from)
					}
				})
			}
		}()
	}
}

func TestAnsweringStaleLeavesTheRefreshRunning(t *testing.T) {
	t.Parallel()
	resp, h := launchText(t, staleWalk, func(c *config) { c.serveStaleTTL = 60 })
	serveStaleWalk(t, resp.port)
	address := func(r *dns.Msg) string {
		if len(r.Answer) == 0 {
			return ""
		}
		return r.Answer[len(r.Answer)-1].(*dns.A).A.String()
	}

	r, err := ask(t.Context(), "udp", h.addr, staleName, time.Second)
	if err != nil || address(r) != "192.0.2.1" {
		t.Fatalf("first answer: %v, %v", r, err)
	}
	time.Sleep(1100 * time.Millisecond)
	r, err = ask(t.Context(), "udp", h.addr, staleName, 2*time.Second)
	if err != nil || address(r) != "192.0.2.1" {
		t.Fatalf("want it served stale: %v, %v", r, err)
	}
	time.Sleep(time.Second)
	r, err = ask(t.Context(), "udp", h.addr, staleName, time.Second)
	if err != nil || address(r) != "192.0.2.2" {
		t.Errorf("want the refreshed answer: %v, %v", r, err)
	}
}

func TestAHalfClosedClientIdlesTheLoop(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, twoSilent, nil)
	c := dial(t, h)
	send(t, c, framed(t, "a.example.com.", 1))
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	before := cpuTicks(t, h)
	time.Sleep(time.Second)
	if spent := cpuTicks(t, h) - before; spent > 20 {
		t.Errorf("hark spent %d ticks of a 100-tick second waiting", spent)
	}
	if _, err := readFrame(c); err != nil {
		t.Errorf("want an answer, got %v", err)
	}
}

func cpuTicks(t *testing.T, h *hark) int {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", h.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	utime, _ := strconv.Atoi(f[11])
	stime, _ := strconv.Atoi(f[12])
	return utime + stime
}
