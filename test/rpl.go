package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type scenario struct {
	rootHints   []netip.Addr
	zones       []string
	sigValidity time.Duration
	// Caps the original TTL signatures carry; 0, none.
	sigOriginalTTL uint32
	clientTimeout  time.Duration
	config         config
	ranges         []*rangeBlock
	steps          []*step
}

type config struct {
	qnameMinimization, prefetch bool
	staggerMs, maxQueries       *int
	minTTL, serveStaleTTL       int
	dns64Prefix                 string
	rebinding                   bool
	allowZones, extraAllow      []string
	stubZones                   []stubZone
	// Set by tests alone; zero is hark's default.
	cacheSize, memory, tcpIdleMs, tcpQueries int
	clients                                  []string
	nofile                                   int
	dotPort                                  uint16
	listenAny                                bool
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
	match    map[string]bool
	drop     bool
	echo     string
	unsigned bool
	reply    dns.MsgHeader
	edns     bool
	ede      int
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

var rplBin string

// The scenario as rpl.zig loads it, which rpl prints. A field it prints and
// this does not know is refused: what the live run cannot honour.
type loaded struct {
	RootHints []netip.AddrPort `json:"root_hints"`
	StubZones []struct {
		Apex    string
		Servers []netip.AddrPort
	} `json:"stub_zones"`
	Ranges []struct {
		Start, End int
		Address    netip.AddrPort
		Entries    []loadedEntry
	}
	Steps []struct {
		N, Seconds, Bound int
		Kind              string
		Entry             *loadedEntry
	}
	Qmin                *bool
	RebindingEnabled    bool     `json:"rebinding_enabled"`
	RebindingAllowZones []string `json:"rebinding_allow_zones"`
	RebindingExtraAllow []string `json:"rebinding_extra_allow"`
	StaggerMs           *int     `json:"stagger_ms"`
	MaxQueries          *int     `json:"max_queries"`
	Dns64Prefix         *struct {
		Bytes [16]byte
		Len   int
	} `json:"dns64_prefix"`
	ServeStaleTTL   int `json:"serve_stale_ttl"`
	MinTTL          int `json:"min_ttl"`
	Prefetch        bool
	ClientTimeoutMs *int     `json:"client_timeout_ms"`
	DnssecZones     []string `json:"dnssec_zones"`
	SigValidity     *int     `json:"sig_validity"`
	SigOriginalTTL  uint32   `json:"sig_original_ttl"`
}

type loadedEntry struct {
	Match          map[string]bool
	DoBit          bool `json:"do_bit"`
	Edns           bool
	Ede            *int
	Drop, Unsigned bool
	Echo           string
	SignAs         string `json:"sign_as"`
	Wildcard       string
	DsFrom         []struct{ Owner, Zone string } `json:"ds_from"`
	QueryLog       []struct {
		Qname string
		Qtype uint16
		Dest  netip.AddrPort
	} `json:"query_log"`
	Message []byte
}

func load(name string, text []byte) (*scenario, error) {
	cmd := exec.Command(rplBin)
	cmd.Stdin = bytes.NewReader(text)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, stderr.Bytes())
	}
	var l loaded
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	sc := &scenario{
		sigValidity:    365 * 24 * time.Hour,
		sigOriginalTTL: l.SigOriginalTTL,
		clientTimeout:  5 * time.Second,
		config: config{
			qnameMinimization: l.Qmin == nil || *l.Qmin,
			prefetch:          l.Prefetch,
			staggerMs:         l.StaggerMs,
			maxQueries:        l.MaxQueries,
			minTTL:            l.MinTTL,
			serveStaleTTL:     l.ServeStaleTTL,
			rebinding:         l.RebindingEnabled,
			allowZones:        l.RebindingAllowZones,
			extraAllow:        l.RebindingExtraAllow,
		},
	}
	for _, h := range l.RootHints {
		sc.rootHints = append(sc.rootHints, h.Addr())
	}
	for _, z := range l.DnssecZones {
		sc.zones = append(sc.zones, dnsutil.Canonical(z))
	}
	if l.SigValidity != nil {
		sc.sigValidity = time.Duration(*l.SigValidity) * time.Second
	}
	if l.ClientTimeoutMs != nil {
		sc.clientTimeout = time.Duration(*l.ClientTimeoutMs) * time.Millisecond
	}
	if p := l.Dns64Prefix; p != nil {
		sc.config.dns64Prefix = netip.PrefixFrom(netip.AddrFrom16(p.Bytes), p.Len).String()
	}
	for _, z := range l.StubZones {
		s := stubZone{zone: z.Apex}
		for _, a := range z.Servers {
			s.servers = append(s.servers, a.Addr())
		}
		sc.config.stubZones = append(sc.config.stubZones, s)
	}
	for _, r := range l.Ranges {
		rg := &rangeBlock{start: r.Start, end: r.End, addr: r.Address.Addr()}
		for _, le := range r.Entries {
			e, err := le.entry()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			rg.entries = append(rg.entries, e)
		}
		sc.ranges = append(sc.ranges, rg)
	}
	for _, s := range l.Steps {
		st := &step{n: s.N, kind: s.Kind, seconds: s.Seconds, max: s.Bound}
		if s.Entry != nil {
			if st.entry, err = s.Entry.entry(); err != nil {
				return nil, fmt.Errorf("%s: step %d: %w", name, s.N, err)
			}
		}
		sc.steps = append(sc.steps, st)
	}
	return sc, nil
}

func (l *loadedEntry) entry() (*entry, error) {
	m := &dns.Msg{Data: l.Message}
	if err := m.Unpack(); err != nil {
		return nil, err
	}
	e := &entry{
		match: map[string]bool{}, drop: l.Drop, echo: l.Echo, unsigned: l.Unsigned,
		reply: m.MsgHeader, edns: l.Edns, ede: -1, signAs: l.SignAs, wildcard: l.Wildcard,
		dsFrom: map[string]string{}, question: m.Question, answer: m.Answer, authority: m.Ns, extra: m.Extra,
	}
	e.reply.Security = l.DoBit
	for k, on := range l.Match {
		if on {
			e.match[k] = true
		}
	}
	if l.Ede != nil {
		e.ede = *l.Ede
	}
	for _, d := range l.DsFrom {
		e.dsFrom[d.Owner] = d.Zone
	}
	for _, r := range l.QueryLog {
		e.queryLog = append(e.queryLog, logRow{qname: r.Qname, qtype: r.Qtype, dest: r.Dest.Addr()})
	}
	return e, nil
}
