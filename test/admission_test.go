package harness

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// Sixteen silent servers outlast a client's 2 s timeout and run a
// resolution to its 7 s deadline.
var admission = func() string {
	silent := make([]int, 16)
	for i := range silent {
		silent[i] = 10 + i
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w(`; hark: root-hints = 127.0.10.1
; hark: qname-minimisation = no

SCENARIO_BEGIN a silent zone beside a live one
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR NOERROR
    SECTION QUESTION
      silent. IN A
    SECTION AUTHORITY`)
	for _, i := range silent {
		w("      silent. 86400 IN NS ns%d.silent.", i)
	}
	w("    SECTION ADDITIONAL")
	for _, i := range silent {
		w("      ns%d.silent. 86400 IN A 127.0.10.%d", i, i)
	}
	w(`  ENTRY_END
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR NOERROR
    SECTION QUESTION
      live. IN A
    SECTION AUTHORITY
      live. 86400 IN NS ns.live.
    SECTION ADDITIONAL
      ns.live. 86400 IN A 127.0.10.2
  ENTRY_END
RANGE_END
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.2
  ENTRY_BEGIN
    MATCH opcode qname
    ADJUST copy_id copy_query
    REPLY QR AA NOERROR
    SECTION QUESTION
      popular.live. IN A
    SECTION ANSWER
      popular.live. 1 IN A 192.0.2.7
  ENTRY_END
  ENTRY_BEGIN
    MATCH opcode qname
    ADJUST copy_id copy_query
    REPLY QR AA NOERROR
    SECTION QUESTION
      hit.live. IN A
    SECTION ANSWER
      hit.live. 3600 IN A 192.0.2.8
  ENTRY_END
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR AA NOERROR
    SECTION QUESTION
      live. IN A
    SECTION ANSWER
      live. 3600 IN A 192.0.2.1
  ENTRY_END
RANGE_END`)
	for _, i := range silent {
		w(`RANGE_BEGIN 0 100
  ADDRESS 127.0.10.%d
  ENTRY_BEGIN
    MATCH opcode
    ADJUST drop
    REPLY QR AA NOERROR
    SECTION QUESTION
      silent. IN A
  ENTRY_END
RANGE_END`, i)
	}
	w("SCENARIO_END")
	return b.String()
}()

func tinyCache(c *config) { c.cacheSize = 32 * 1024 }

func fire(t *testing.T, h *hark, names ...string) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(h.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, n := range names {
		m := dns.NewMsg(n, dns.TypeA)
		if err := m.Pack(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(m.Data); err != nil {
			t.Fatal(err)
		}
	}
}

func silentNames() []string {
	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprintf("q%d.silent.", i)
	}
	return names
}

// The second question wakes the loop to look at its timers.
func advance(t *testing.T, h *hark, seconds int) {
	t.Helper()
	if err := advanceClock(t.Context(), h.addr, seconds); err != nil {
		t.Fatal(err)
	}
	wantRcode(t, h.addr, "localhost.", dns.RcodeSuccess, 5*time.Second)
}

func TestLateWaitersMakeRoomForNewQuestions(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, admission, tinyCache)
	fire(t, h, silentNames()...)
	wantSilence(t, h.addr, "a.live.", 300*time.Millisecond)
	advance(t, h, 3)
	fire(t, h, "b.live.")
	advance(t, h, 2)
	wantRcode(t, h.addr, "c.live.", dns.RcodeSuccess, 2*time.Second)
	if n := stats(t, h, "clients.unanswered.reaped")[0]; n == 0 {
		t.Error("no client was reaped")
	}
}

func TestACrowdedQueueShedsNovelNamesOnly(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, admission, nil)
	for _, name := range []string{"hit.live.", "popular.live."} {
		wantRcode(t, h.addr, name, dns.RcodeSuccess, 5*time.Second)
	}
	advance(t, h, 2)

	// A loopback datagram takes ~1 KB of hark's 2 MB receive buffer: queued
	// while it is stopped, the burst overflows it.
	burst := append([]string{"novel.live.", "popular.live."}, slices.Repeat([]string{"hit.live."}, 3000)...)
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(h.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetReadBuffer(8 << 20); err != nil {
		t.Fatal(err)
	}
	wires := make([][]byte, len(burst))
	for i, name := range burst {
		m := dns.NewMsg(name, dns.TypeA)
		if err := m.Pack(); err != nil {
			t.Fatal(err)
		}
		wires[i] = m.Data
	}
	pid := h.cmd.Process.Pid
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	for _, w := range wires {
		if _, err = c.Write(w); err != nil {
			break
		}
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	answered := map[string]int{}
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		if timedOut(err) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		r := &dns.Msg{Data: buf[:n]}
		if err := r.Unpack(); err != nil {
			t.Fatal(err)
		}
		if r.Rcode != dns.RcodeSuccess || len(r.Question) != 1 {
			t.Fatalf("burst reply is not a NOERROR answer:\n%v", r)
		}
		answered[strings.ToLower(r.Question[0].Header().Name)]++
	}
	if n := answered["hit.live."]; n <= 1000 {
		t.Errorf("hit.live. answered %d times, want over 1000", n)
	}
	if n := answered["popular.live."]; n != 1 {
		t.Errorf("popular.live. answered %d times, want 1", n)
	}
	if n := answered["novel.live."]; n != 0 {
		t.Errorf("novel.live. answered %d times, want 0", n)
	}
	if n := stats(t, h, "clients.unanswered.shed")[0]; n != 1 {
		t.Errorf("shed %d, want 1", n)
	}
	wantRcode(t, h.addr, "novel.live.", dns.RcodeSuccess, 5*time.Second)
}

func TestTCPTurnedAwayIsServfailOverQuota(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, admission, tinyCache)
	fire(t, h, silentNames()...)
	c, err := net.DialTimeout("tcp", h.addr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, r := range pipeline(t, c, "x.live.", "y.live.") {
		if r.Rcode != dns.RcodeServerFailure || !slices.Equal(edes(r), []uint16{32}) {
			t.Errorf("want SERVFAIL with EDE 32 (RFC 8914), got:\n%v", r)
		}
	}
	wantSilence(t, h.addr, "x.live.", 300*time.Millisecond)
	if r := pipeline(t, c, "localhost.")[0]; r.Rcode != dns.RcodeSuccess {
		t.Errorf("localhost. over the same connection:\n%v", r)
	}
}

func pipeline(t *testing.T, c net.Conn, names ...string) []*dns.Msg {
	t.Helper()
	var wire []byte
	for _, n := range names {
		m := dns.NewMsg(n, dns.TypeA)
		m.UDPSize = payload
		f, err := frame(m)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, f...)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	replies := make([]*dns.Msg, len(names))
	for i := range replies {
		r, err := readFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		replies[i] = r
	}
	return replies
}
