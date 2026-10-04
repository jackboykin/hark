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

// stats reads dotted counters (clients.unanswered.reaped) off a fresh USR1 dump,
// which ends with its window line.
func stats(t *testing.T, h *hark, names ...string) []int {
	t.Helper()
	before := strings.Count(h.log(), "stats window (")
	if err := h.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	log := h.log()
	for deadline := time.Now().Add(2 * time.Second); strings.Count(log, "stats window (") == before; log = h.log() {
		if time.Now().After(deadline) {
			t.Fatalf("no stats dump within 2s; log:\n%s", log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	out := make([]int, len(names))
	for i, name := range names {
		m := regexp.MustCompile(`stats ` + regexp.QuoteMeta(name) + ` +(\d+)`).FindAllStringSubmatch(log, -1)
		if m == nil {
			t.Fatalf("no %s counter in log:\n%s", name, log)
		}
		out[i], _ = strconv.Atoi(m[len(m)-1][1])
	}
	return out
}
