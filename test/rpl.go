package harness

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type scenario struct {
	rootHints     []netip.Addr
	zones         []string
	sigValidity   time.Duration
	clientTimeout time.Duration
	config        config
	ranges        []*rangeBlock
	steps         []*step
}

type config struct {
	qnameMinimization, minimalResponses, prefetch bool
	staggerMs, maxQueries                         *int
	minTTL, serveStaleTTL                         int
	dns64Prefix                                   string
	rebinding                                     bool
	allowZones, extraAllow                        []string
	stubZones                                     []stubZone
	// Set by tests alone; zero is hark's default.
	cacheSize, tcpIdleMs int
	allowFrom            []string
	nofile               int
}

type stubZone struct {
	zone    string
	servers []netip.Addr
}

type rangeBlock struct {
	start, end int
	addr       netip.Addr
	entries    []*entry
}

type entry struct {
	match  map[string]bool
	adjust map[string]bool
	reply  dns.MsgHeader
	edns   bool
	ede    int
	// How a scenario forges.
	signAs                   string
	wildcard                 string
	dsFrom                   map[string]string
	question                 []dns.RR
	answer, authority, extra []dns.RR
	queryLog                 []logRow
}

type logRow struct {
	qname string
	qtype uint16
	dest  netip.Addr
}

func (w logRow) String() string {
	return fmt.Sprintf("%s %s %v", w.qname, dnsutil.TypeToString(w.qtype), w.dest)
}

type step struct {
	n       int
	kind    string
	entry   *entry
	seconds int
	max     int
}

var (
	directiveRE = regexp.MustCompile(`^\s*;\s*hark\s*:\s*([a-z0-9\-]+)\s*=\s*(.+?)\s*$`)
	elapseRE    = regexp.MustCompile(`ELAPSE\s+(\d+)`)

	matchFlags = set("opcode", "qname", "qtype", "qclass", "question", "subdomain", "tcp", "udp",
		"all", "answer", "authority", "additional", "flags", "rcode", "ttl", "order")
	adjustFlags = set("copy_id", "copy_query", "force_upper_qname", "drop_question", "drop",
		"unsigned")
	sections = set("QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL", "QUERY_LOG")
	rcodes   = map[string]uint16{
		"NOERROR": dns.RcodeSuccess, "FORMERR": dns.RcodeFormatError, "SERVFAIL": dns.RcodeServerFailure,
		"NXDOMAIN": dns.RcodeNameError, "NOTIMP": dns.RcodeNotImplemented, "REFUSED": dns.RcodeRefused,
		"YXDOMAIN": dns.RcodeYXDomain,
	}
)

func set(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, k := range s {
		m[k] = true
	}
	return m
}

func parse(name string, text []byte) (*scenario, error) {
	p := parser{sc: &scenario{
		sigValidity:   365 * 24 * time.Hour,
		clientTimeout: 5 * time.Second,
		config:        config{qnameMinimization: true, minimalResponses: true},
	}}
	for i, raw := range strings.Split(string(text), "\n") {
		if err := p.line(raw); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, i+1, err)
		}
		if p.done {
			return p.sc, nil
		}
	}
	return nil, fmt.Errorf("%s: %w", name, cmp.Or(p.unclosed(), errors.New("missing SCENARIO_END")))
}

type parser struct {
	sc        *scenario
	begun     bool
	done      bool
	rng       *rangeBlock
	wantEntry *step
	entry     *entry
	section   string
}

func (p *parser) line(raw string) error {
	line := strings.TrimSpace(raw)
	if line == "" {
		return nil
	}
	if line[0] == ';' {
		if m := directiveRE.FindStringSubmatch(raw); m != nil {
			return p.directive(m[1], m[2])
		}
		return nil
	}
	f := strings.Fields(line)
	if !p.begun {
		if f[0] != "SCENARIO_BEGIN" {
			return fmt.Errorf("expected SCENARIO_BEGIN, got %q", line)
		}
		p.begun = true
		return nil
	}
	if f[0] == "SCENARIO_END" {
		if err := p.unclosed(); err != nil {
			return err
		}
	}
	if p.entry != nil {
		return p.entryLine(line, f)
	}
	if p.wantEntry != nil && f[0] != "ENTRY_BEGIN" {
		return fmt.Errorf("STEP %d %s requires an ENTRY block", p.wantEntry.n, p.wantEntry.kind)
	}
	if p.rng != nil && !slices.Contains([]string{"ADDRESS", "ENTRY_BEGIN", "RANGE_END"}, f[0]) {
		return fmt.Errorf("unexpected in RANGE: %q", line)
	}
	switch f[0] {
	case "SCENARIO_END":
		p.done = true
	case "RANGE_BEGIN":
		if len(f) != 3 {
			return errors.New("RANGE_BEGIN takes <start> <end>")
		}
		start, err1 := strconv.Atoi(f[1])
		end, err2 := strconv.Atoi(f[2])
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		p.rng = &rangeBlock{start: start, end: end}
	case "ADDRESS":
		if p.rng == nil || len(f) != 2 {
			return errors.New("ADDRESS takes one IP inside a RANGE")
		}
		a, err := netip.ParseAddr(f[1])
		p.rng.addr = a
		return err
	case "RANGE_END":
		if p.rng == nil {
			return errors.New("RANGE_END outside a RANGE")
		}
		if !p.rng.addr.IsValid() {
			if len(p.sc.rootHints) == 0 {
				return errors.New("RANGE without ADDRESS and no root-hints to default to")
			}
			p.rng.addr = p.sc.rootHints[0]
		}
		p.sc.ranges = append(p.sc.ranges, p.rng)
		p.rng = nil
	case "ENTRY_BEGIN":
		if p.rng == nil && p.wantEntry == nil {
			return errors.New("ENTRY_BEGIN outside a RANGE or STEP")
		}
		p.entry = &entry{match: map[string]bool{}, adjust: map[string]bool{}, ede: -1, dsFrom: map[string]string{}}
		p.section = ""
	case "STEP":
		return p.stepLine(line, f)
	default:
		return fmt.Errorf("unexpected %q", line)
	}
	return nil
}

func (p *parser) unclosed() error {
	switch {
	case p.entry != nil:
		return errors.New("missing ENTRY_END")
	case p.rng != nil:
		return errors.New("missing RANGE_END")
	}
	return nil
}

func (p *parser) stepLine(line string, f []string) error {
	if len(f) < 3 {
		return errors.New("STEP takes <n> <KIND> ...")
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return err
	}
	if slices.ContainsFunc(p.sc.steps, func(s *step) bool { return s.n == n }) {
		return fmt.Errorf("duplicate STEP %d", n)
	}
	s := &step{n: n, kind: f[2]}
	switch s.kind {
	case "QUERY", "CHECK_ANSWER", "CHECK_QUERY_LOG", "CHECK_OUT_QUERY":
		p.wantEntry = s
	case "TIME_PASSES":
		// Refused bare: advancing by nothing would pass vacuously.
		m := elapseRE.FindStringSubmatch(line)
		if m == nil {
			return errors.New("TIME_PASSES needs ELAPSE <n>")
		}
		s.seconds, _ = strconv.Atoi(m[1])
	case "CHECK_MAX_QUERIES":
		if len(f) != 4 {
			return errors.New("CHECK_MAX_QUERIES takes a single integer bound")
		}
		if s.max, err = strconv.Atoi(f[3]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown STEP kind %q", s.kind)
	}
	p.sc.steps = append(p.sc.steps, s)
	return nil
}

func (p *parser) entryLine(line string, f []string) error {
	e := p.entry
	switch f[0] {
	case "ENTRY_END":
		if p.wantEntry != nil {
			p.wantEntry.entry = e
			p.wantEntry = nil
		} else {
			p.rng.entries = append(p.rng.entries, e)
		}
		p.entry = nil
	case "MATCH":
		for _, t := range f[1:] {
			t = strings.ToLower(t)
			if code, ok := strings.CutPrefix(t, "ede="); ok {
				n, err := strconv.ParseUint(code, 10, 16)
				if err != nil {
					return err
				}
				e.ede = int(n)
			} else if !matchFlags[t] {
				return fmt.Errorf("unknown MATCH flag %q", t)
			} else {
				e.match[t] = true
			}
		}
	case "ADJUST":
		for _, t := range f[1:] {
			t = strings.ToLower(t)
			if !adjustFlags[t] {
				return fmt.Errorf("unknown ADJUST flag %q", t)
			}
			e.adjust[t] = true
		}
	case "REPLY":
		for _, t := range f[1:] {
			if err := e.replyToken(t); err != nil {
				return err
			}
		}
	case "SIGN_AS":
		if len(f) != 2 {
			return fmt.Errorf("SIGN_AS takes one zone name: %q", line)
		}
		e.signAs = dnsutil.Canonical(f[1])
	case "WILDCARD":
		if len(f) != 2 || !strings.HasPrefix(f[1], "*.") {
			return fmt.Errorf("WILDCARD takes one wildcard owner: %q", line)
		}
		e.wildcard = dnsutil.Fqdn(f[1])
	case "SECTION":
		if len(f) != 2 || !sections[f[1]] {
			return fmt.Errorf("bad SECTION: %q", line)
		}
		p.section = f[1]
	default:
		return p.record(line, f)
	}
	return nil
}

func (e *entry) replyToken(t string) error {
	h := &e.reply
	switch t {
	case "QR":
		h.Response = true
	case "AA":
		h.Authoritative = true
	case "TC":
		h.Truncated = true
	case "RD":
		h.RecursionDesired = true
	case "RA":
		h.RecursionAvailable = true
	case "AD":
		h.AuthenticatedData = true
	case "CD":
		h.CheckingDisabled = true
	case "DO":
		h.Security = true
	case "EDNS":
		e.edns = true
	default:
		r, ok := rcodes[t]
		if !ok {
			return fmt.Errorf("unknown REPLY token %q", t)
		}
		h.Rcode = r
	}
	return nil
}

// dns.New defaults to origin "." and TTL 3600, testbound's.
func (p *parser) record(line string, f []string) error {
	e := p.entry
	switch p.section {
	case "":
		return fmt.Errorf("RR outside SECTION: %q", line)
	case "QUERY_LOG":
		if len(f) != 2 && len(f) != 3 {
			return fmt.Errorf("bad QUERY_LOG line (want `qname qtype [dest]`): %q", line)
		}
		t, err := dnsutil.StringToType(f[1])
		if err != nil {
			return err
		}
		row := logRow{qname: dnsutil.Canonical(f[0]), qtype: t}
		if len(f) == 3 {
			if row.dest, err = netip.ParseAddr(f[2]); err != nil {
				return err
			}
		}
		e.queryLog = append(e.queryLog, row)
		return nil
	}
	// The key behind a DS digest exists only at run time.
	var from string
	if i := slices.IndexFunc(f, func(s string) bool { return strings.EqualFold(s, "PLACEHOLDER") }); i > 0 && strings.EqualFold(f[i-1], "DS") {
		if i+1 < len(f) {
			from = dnsutil.Canonical(f[i+1])
		}
		line = strings.Join(f[:i], " ")
	}
	rr, err := dns.New(line)
	if err != nil {
		return fmt.Errorf("bad RR (%s): %w", p.section, err)
	}
	if _, ok := rr.(*dns.OPT); ok {
		return fmt.Errorf("OPT in %s: the responder owns its reply's OPT; a scenario's would be a second on the wire (RFC 6891 §6.1.1)", p.section)
	}
	if from != "" {
		e.dsFrom[dnsutil.Canonical(rr.Header().Name)] = from
	}
	// The library packs types as written; the wire wants them ascending.
	switch rr := rr.(type) {
	case *dns.NSEC:
		slices.Sort(rr.TypeBitMap)
	case *dns.NSEC3:
		slices.Sort(rr.TypeBitMap)
	}
	switch p.section {
	case "QUESTION":
		e.question = append(e.question, rr)
	case "ANSWER":
		e.answer = append(e.answer, rr)
	case "AUTHORITY":
		e.authority = append(e.authority, rr)
	case "ADDITIONAL":
		e.extra = append(e.extra, rr)
	}
	return nil
}

func (p *parser) directive(key, val string) error {
	sc, c := p.sc, &p.sc.config
	yes := slices.Contains([]string{"yes", "true", "on", "1"}, strings.ToLower(val))
	number := func(dst *int) (err error) {
		*dst, err = strconv.Atoi(val)
		return err
	}
	switch key {
	case "root-hints":
		sc.rootHints = nil
		for h := range strings.SplitSeq(val, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(h))
			if err != nil {
				return err
			}
			sc.rootHints = append(sc.rootHints, a)
		}
	case "stub-zone":
		f := strings.Fields(val)
		if len(f) < 2 {
			return fmt.Errorf("stub-zone takes a zone and its servers: %q", val)
		}
		z := stubZone{zone: f[0]}
		for _, s := range f[1:] {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return err
			}
			z.servers = append(z.servers, a)
		}
		c.stubZones = append(c.stubZones, z)
	case "qname-minimisation":
		c.qnameMinimization = yes
	case "minimal-responses":
		c.minimalResponses = yes
	case "prefetch":
		c.prefetch = yes
	case "rebinding-enabled":
		c.rebinding = yes
	case "rebinding-allow-zone":
		c.allowZones = append(c.allowZones, val)
	case "rebinding-extra-allow":
		c.extraAllow = append(c.extraAllow, val)
	case "stagger-ms":
		c.staggerMs = new(0)
		return number(c.staggerMs)
	case "max-queries":
		c.maxQueries = new(0)
		return number(c.maxQueries)
	case "min-ttl":
		return number(&c.minTTL)
	case "serve-stale-ttl":
		return number(&c.serveStaleTTL)
	case "dns64-prefix":
		c.dns64Prefix = val
	case "sig-validity":
		s, err := strconv.Atoi(val)
		sc.sigValidity = time.Duration(s) * time.Second
		return err
	case "client-timeout":
		s, err := strconv.ParseFloat(val, 64)
		sc.clientTimeout = time.Duration(s * float64(time.Second))
		return err
	case "dnssec-zone":
		z := dnsutil.Canonical(val)
		if len(sc.zones) == 0 && z != "." {
			return fmt.Errorf("first dnssec-zone must be . (hark anchors trust at the root only); got %q", z)
		}
		if !slices.Contains(sc.zones, z) {
			sc.zones = append(sc.zones, z)
		}
	default:
		return fmt.Errorf("unknown hark directive %q", key)
	}
	return nil
}
