package harness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// IPv6's minimum MTU (1280) minus the IPv6 and UDP headers (RFC 9715
// Appendix A).
const payload = 1232

func askEntry(ctx context.Context, addr netip.AddrPort, e *entry, timeout time.Duration) (*dns.Msg, error) {
	if len(e.question) == 0 {
		return nil, errors.New("QUERY entry has no QUESTION")
	}
	m := &dns.Msg{Question: e.question[:1]}
	h := e.reply
	m.Response, m.Authoritative, m.Truncated, m.RecursionDesired = h.Response, h.Authoritative, h.Truncated, h.RecursionDesired
	m.RecursionAvailable, m.AuthenticatedData, m.CheckingDisabled = h.RecursionAvailable, h.AuthenticatedData, h.CheckingDisabled
	if h.Security || e.edns {
		m.UDPSize, m.Security = payload, h.Security
	}
	return exchange(ctx, "udp", addr, m, timeout)
}

func advanceClock(ctx context.Context, addr netip.AddrPort, seconds int) error {
	m := dns.NewMsg(fmt.Sprintf("_advance-clock.%d.testharness.invalid.", seconds), dns.TypeTXT)
	_, err := exchange(ctx, "udp", addr, m, 5*time.Second)
	return err
}

func edes(r *dns.Msg) []uint16 {
	var codes []uint16
	for _, o := range r.Pseudo {
		if ede, ok := o.(*dns.EDE); ok {
			codes = append(codes, ede.InfoCode)
		}
	}
	return codes
}

// Exchange checks only the ID.
func exchange(ctx context.Context, network string, addr netip.AddrPort, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	m.ID = dns.ID()
	c := &dns.Client{Transport: &dns.Transport{Dialer: &net.Dialer{Timeout: timeout}, ReadTimeout: timeout, WriteTimeout: timeout}}
	r, _, err := c.Exchange(ctx, m, network, addr.String())
	if err != nil {
		return nil, err
	}
	if r.Opcode != m.Opcode || !slices.EqualFunc(r.Question, m.Question, sameQuestion) {
		return nil, fmt.Errorf("reply does not answer the query:\n%v\n%v", m, r)
	}
	return r, nil
}

func sameQuestion(a, b dns.RR) bool {
	return strings.EqualFold(a.Header().Name, b.Header().Name) && a.Header().Class == b.Header().Class && dns.RRToType(a) == dns.RRToType(b)
}

func checkAnswer(r *dns.Msg, e *entry) error {
	all := len(e.match) == 0 || e.match["all"]
	has := func(k string) bool { return all || e.match[k] }
	ttl := e.match["ttl"]
	want := e.reply
	// Rcode shares the header with the flag bits.
	if (has("rcode") || has("flags")) && r.Rcode != want.Rcode {
		return fmt.Errorf("rcode mismatch: expected %s got %s", dnsutil.RcodeToString(want.Rcode), dnsutil.RcodeToString(r.Rcode))
	}
	if e.ede >= 0 {
		if codes := edes(r); !slices.Contains(codes, uint16(e.ede)) {
			return fmt.Errorf("EDE mismatch: expected %d got %v", e.ede, codes)
		}
	}
	flags := func(h dns.MsgHeader) [5]bool {
		return [5]bool{h.Response, h.Authoritative, h.Truncated, h.RecursionAvailable, h.AuthenticatedData}
	}
	if has("flags") && flags(r.MsgHeader) != flags(want) {
		return fmt.Errorf("flags mismatch (qr aa tc ra ad): expected %v got %v", flags(want), flags(r.MsgHeader))
	}
	if has("question") && !slices.EqualFunc(r.Question, e.question, sameQuestion) {
		return fmt.Errorf("QUESTION mismatch:\n  got:  %v\n  want: %v", r.Question, e.question)
	}
	for _, s := range []struct {
		name      string
		got, want []dns.RR
	}{{"answer", r.Answer, e.answer}, {"authority", r.Ns, e.authority}, {"additional", r.Extra, e.extra}} {
		if !has(s.name) {
			continue
		}
		if err := compareSection(s.got, s.want, ttl); err != nil {
			return fmt.Errorf("%s mismatch:\n%w", strings.ToUpper(s.name), err)
		}
	}
	return nil
}

// A step may straddle a second boundary; the bugs these scenarios catch
// are hundreds of seconds wide.
const ttlSlack = 3

func compareSection(got, want []dns.RR, ttl bool) error {
	// A signature minted at run time can't be spelled.
	isSig := func(rr dns.RR) bool { return dns.RRToType(rr) == dns.TypeRRSIG }
	if !slices.ContainsFunc(want, isSig) {
		got = slices.DeleteFunc(slices.Clone(got), isSig)
	}
	left := slices.Clone(want)
	for _, g := range got {
		if i := slices.IndexFunc(left, func(w dns.RR) bool { return sameRR(g, w, ttl) }); i >= 0 {
			left = slices.Delete(left, i, i+1)
		}
	}
	if len(got) == len(want) && len(left) == 0 {
		return nil
	}
	show := func(rrs []dns.RR) string {
		var b strings.Builder
		for _, rr := range rrs {
			fmt.Fprintf(&b, "    %v\n", rr)
		}
		return b.String()
	}
	return fmt.Errorf("  got:\n%s  want:\n%s", show(got), show(want))
}

// hark scrubs 0x20 case off owners.
func sameRR(a, b dns.RR, ttl bool) bool {
	ha, hb := a.Header(), b.Header()
	return ha.Name == hb.Name && ha.Class == hb.Class && dns.RRToType(a) == dns.RRToType(b) &&
		(!ttl || max(ha.TTL, hb.TTL)-min(ha.TTL, hb.TTL) <= ttlSlack) && rdata(a) == rdata(b)
}

// hark leaves names inside rdata as it got them.
func rdata(rr dns.RR) string {
	if sig, ok := rr.(*dns.RRSIG); ok {
		return strings.ToLower(fmt.Sprintf("%d %d %d %s", sig.TypeCovered, sig.Algorithm, sig.Labels, sig.SignerName))
	}
	return strings.ToLower(rr.Data().String())
}

func checkQueryLog(log []query, e *entry) error {
	if len(e.queryLog) == 0 {
		return errors.New("CHECK_QUERY_LOG entry has no SECTION QUERY_LOG rows")
	}
	matches := func(q query, w logRow) bool {
		return q.qname == w.qname && q.qtype == w.qtype && (!w.dest.IsValid() || q.addr == w.dest)
	}
	if e.match["order"] {
		i := 0
		for _, q := range log {
			if i < len(e.queryLog) && matches(q, e.queryLog[i]) {
				i++
			}
		}
		if i != len(e.queryLog) {
			return fmt.Errorf("CHECK_QUERY_LOG order mismatch: row %d %v not found in order", i, e.queryLog[i])
		}
		return nil
	}
	for _, w := range e.queryLog {
		if !slices.ContainsFunc(log, func(q query) bool { return matches(q, w) }) {
			return fmt.Errorf("CHECK_QUERY_LOG missing %v", w)
		}
	}
	return nil
}

func checkOutQuery(q query, e *entry) error {
	if len(e.question) == 0 {
		return errors.New("CHECK_OUT_QUERY entry has no QUESTION")
	}
	question := len(e.match) == 0 || e.match["question"]
	w := e.question[0]
	var bad []string
	if (question || e.match["qname"]) && q.qname != strings.ToLower(w.Header().Name) {
		bad = append(bad, fmt.Sprintf("qname: got %s, want %s", q.qname, strings.ToLower(w.Header().Name)))
	}
	if (question || e.match["qtype"]) && q.qtype != dns.RRToType(w) {
		bad = append(bad, fmt.Sprintf("qtype: got %s, want %s", dnsutil.TypeToString(q.qtype), dnsutil.TypeToString(dns.RRToType(w))))
	}
	if (question || e.match["qclass"]) && q.qclass != w.Header().Class {
		bad = append(bad, fmt.Sprintf("qclass: got %s, want %s", dnsutil.ClassToString(q.qclass), dnsutil.ClassToString(w.Header().Class)))
	}
	if bad != nil {
		return fmt.Errorf("CHECK_OUT_QUERY mismatch (dest %s):\n  %s", q.addr, strings.Join(bad, "\n  "))
	}
	return nil
}
