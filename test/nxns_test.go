package harness

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// An evil root for NXNSAttack (CVE-2020-12667).
const (
	nxnsRoot = "n"
	// hark fetches at most 3.
	nxnsFanout = 12
	// hark's depth cap bites first.
	nxnsMaxDepth = 5
)

type evilRoot struct {
	conn  *net.UDPConn
	total atomic.Int64
	wg    sync.WaitGroup
}

func serveEvilRoot(t *testing.T) *evilRoot {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := &evilRoot{conn: c}
	t.Cleanup(func() { c.Close(); e.wg.Wait() })
	e.wg.Go(func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := &dns.Msg{Data: buf[:n]}
			if q.Unpack() != nil || len(q.Question) == 0 {
				continue
			}
			if m := e.reply(q); m.Pack() == nil {
				c.WriteToUDPAddrPort(m.Data, from)
			}
		}
	})
	return e
}

func (e *evilRoot) port() uint16 { return e.conn.LocalAddr().(*net.UDPAddr).AddrPort().Port() }

func (e *evilRoot) reply(q *dns.Msg) *dns.Msg {
	m := replyTo(q)
	name := q.Question[0].Header().Name
	if name == "." {
		m.Authoritative = true
		return m
	}
	tld := strings.TrimSuffix(name, ".")
	tld = tld[strings.LastIndexByte(tld, '.')+1:]
	path, ours := decodePath(tld)
	if ours {
		e.total.Add(1)
	}
	if !ours || len(path) >= nxnsMaxDepth {
		m.Authoritative = true
		soa, _ := dns.New(name + " 300 IN SOA ns.invalid. hostmaster.invalid. 1 7200 3600 86400 300")
		m.Ns = []dns.RR{soa}
		return m
	}
	for i := range nxnsFanout {
		ns, _ := dns.New(fmt.Sprintf("%s. 86400 IN NS ns.%s.", tld, childLabel(append(path, i))))
		m.Ns = append(m.Ns, ns)
	}
	return m
}

func childLabel(path []int) string {
	var b strings.Builder
	b.WriteString(nxnsRoot)
	for _, i := range path {
		fmt.Fprintf(&b, "-%d", i)
	}
	return b.String()
}

// Case-blind (RFC 1034 §3.1): hark's 0x20 turns "n" into "N" half the time,
// and an uncounted NODATA for it would be cached and zero the count.
func decodePath(label string) (path []int, ours bool) {
	label = strings.ToLower(label)
	if label == nxnsRoot {
		return nil, true
	}
	rest, ok := strings.CutPrefix(label, nxnsRoot+"-")
	if !ok {
		return nil, false
	}
	for s := range strings.SplitSeq(rest, "-") {
		if s == "" {
			continue
		}
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, false
		}
		path = append(path, i)
	}
	return path, true
}

// Three NS chased per referral to the depth cap is 1+3+9+27 = 40 queries;
// chasing every name runs into max-queries (100). The bound guards the
// fanout cap.
func TestGluelessNSFanoutIsBounded(t *testing.T) {
	t.Parallel()
	const bound = 60
	evil := serveEvilRoot(t)
	sc := &scenario{
		rootHints: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		config:    config{qnameMinimization: true, minimalResponses: true},
	}
	ctx, stop := context.WithCancel(t.Context())
	h, err := startHark(ctx, t, harkBin, sc, evil.port(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ask(t.Context(), "udp", h.addr, "victim."+nxnsRoot+".", 20*time.Second); err != nil {
		t.Error(err)
	}
	if h.exited() {
		t.Fatalf("hark died:\n%s", h.log())
	}
	stop()
	<-h.done
	switch n := evil.total.Load(); {
	case n == 0:
		t.Fatal("the evil root saw no queries: the wiring broke")
	case n > bound:
		t.Errorf("NXNSAttack amplification: one client query provoked %d upstream queries, bound %d", n, bound)
	}
}
