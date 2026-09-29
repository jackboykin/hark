package harness

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// These run in parallel only after the scenario flood, which would stretch
// hark's timers: Go holds parallel top-level tests until the sequential
// ones end, and TestScenarios ends with its last subtest.

func launchText(t *testing.T, text string, tune func(*config)) (*responder, *hark) {
	t.Helper()
	sc, err := parse(t.Name(), []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if tune != nil {
		tune(&sc.config)
	}
	return launch(t.Context(), t, sc)
}

func ask(ctx context.Context, network string, addr netip.AddrPort, name string, timeout time.Duration) (*dns.Msg, error) {
	return exchange(ctx, network, addr, dns.NewMsg(name, dns.TypeA), timeout)
}

func wantRcode(t *testing.T, addr netip.AddrPort, name string, rcode uint16, timeout time.Duration) {
	t.Helper()
	r, err := ask(t.Context(), "udp", addr, name, timeout)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if r.Rcode != rcode {
		t.Fatalf("%s: rcode %s, want %s", name, dnsutil.RcodeToString(r.Rcode), dnsutil.RcodeToString(rcode))
	}
}

func wantSilence(t *testing.T, addr netip.AddrPort, name string, timeout time.Duration) {
	t.Helper()
	r, err := ask(t.Context(), "udp", addr, name, timeout)
	if !timedOut(err) {
		t.Fatalf("%s: want no reply within %v, got %v %v", name, timeout, r, err)
	}
}

func timedOut(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

var counter = regexp.MustCompile(`([a-z]+) (\d+)`)

func stats(t *testing.T, h *hark, prefix string, names ...string) []int {
	t.Helper()
	before := strings.Count(h.log(), prefix)
	if err := h.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	log := h.log()
	for deadline := time.Now().Add(2 * time.Second); strings.Count(log, prefix) == before; log = h.log() {
		if time.Now().After(deadline) {
			t.Fatalf("no %q line within 2s; log:\n%s", prefix, log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	line, _, _ := strings.Cut(log[strings.LastIndex(log, prefix):], "\n")
	counts := map[string]int{}
	for _, m := range counter.FindAllStringSubmatch(line, -1) {
		counts[m[1]], _ = strconv.Atoi(m[2])
	}
	out := make([]int, len(names))
	for i, name := range names {
		n, ok := counts[name]
		if !ok {
			t.Fatalf("no %s counter in %q", name, line)
		}
		out[i] = n
	}
	return out
}
