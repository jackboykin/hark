package harness

import (
	"cmp"
	"crypto"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type key struct {
	zone   string
	dnskey *dns.DNSKEY
	priv   crypto.Signer
	ds     *dns.DS
	answer []dns.RR
}

type signer struct {
	keys                  []*key
	inception, expiration uint32
	// Where each zone signed: only those addresses answer its DNSKEY.
	served map[netip.Addr][]*key
}

func newSigner(zones []string) (*signer, error) {
	s := &signer{served: map[netip.Addr][]*key{}}
	for _, z := range zones {
		dk := &dns.DNSKEY{Hdr: dns.Header{Name: z, Class: dns.ClassINET, TTL: 3600}}
		dk.Flags, dk.Protocol, dk.Algorithm = dns.FlagZONE, 3, dns.ECDSAP256SHA256
		priv, err := dk.Generate(256)
		// The library reads key tag 0 as unset.
		for err == nil && dk.KeyTag() == 0 {
			priv, err = dk.Generate(256)
		}
		if err != nil {
			return nil, err
		}
		s.keys = append(s.keys, &key{zone: z, dnskey: dk, priv: priv.(crypto.Signer), ds: dk.ToDS(dns.SHA256)})
	}
	return s, nil
}

func (s *signer) anchor() string {
	ds := s.keys[0].ds
	return fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
}

func (s *signer) bake(ranges []*rangeBlock, validity time.Duration) error {
	now := time.Now()
	s.inception, s.expiration = uint32(now.AddDate(0, 0, -1).Unix()), uint32(now.Add(validity).Unix())
	for _, k := range s.keys {
		sig, err := s.sign(k, []dns.RR{k.dnskey}, "")
		if err != nil {
			return err
		}
		k.answer = []dns.RR{k.dnskey, sig}
	}
	for _, r := range ranges {
		for _, e := range r.entries {
			if e.adjust["unsigned"] {
				continue
			}
			var forced *key
			if e.signAs != "" {
				if forced = s.named(e.signAs); forced == nil {
					return fmt.Errorf("SIGN_AS %s: no such dnssec-zone", e.signAs)
				}
			}
			cuts := delegationCuts(e)
			var err error
			if e.answer, err = s.section(e, e.answer, cuts, forced, r.addr, e.wildcard); err != nil {
				return err
			}
			if e.authority, err = s.section(e, e.authority, cuts, forced, r.addr, ""); err != nil {
				return err
			}
			if e.extra, err = s.section(e, e.extra, cuts, forced, r.addr, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

// The SOA clause keeps a NODATA carrying its own apex NS from reading as a
// cut at the apex.
func delegationCuts(e *entry) []string {
	var cuts []string
	add := func(rr dns.RR) {
		if n := dnsutil.Canonical(rr.Header().Name); !slices.Contains(cuts, n) {
			cuts = append(cuts, n)
		}
	}
	for _, rr := range slices.Concat(e.answer, e.authority, e.extra) {
		if dns.RRToType(rr) == dns.TypeDS {
			add(rr)
		}
	}
	isSOA := func(rr dns.RR) bool { return dns.RRToType(rr) == dns.TypeSOA }
	if len(e.answer) == 0 && !slices.ContainsFunc(e.authority, isSOA) {
		for _, rr := range e.authority {
			if dns.RRToType(rr) == dns.TypeNS {
				add(rr)
			}
		}
	}
	return cuts
}

func (s *signer) section(e *entry, rrs []dns.RR, cuts []string, forced *key, addr netip.Addr, wildcard string) ([]dns.RR, error) {
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok && ds.Digest == "" {
			zone := cmp.Or(e.dsFrom[dnsutil.Canonical(ds.Hdr.Name)], ds.Hdr.Name)
			k := s.named(zone)
			if k == nil {
				return nil, fmt.Errorf("placeholder DS at %s but no dnssec-zone %s to take a digest of", ds.Hdr.Name, zone)
			}
			ds.DS = k.ds.DS
		}
	}
	originals, out := rrs, slices.Clone(rrs)
	for i, head := range originals {
		owner, t := head.Header().Name, dns.RRToType(head)
		sameSet := func(rr dns.RR) bool { return dns.RRToType(rr) == t && strings.EqualFold(rr.Header().Name, owner) }
		if t == dns.TypeRRSIG || slices.ContainsFunc(originals[:i], sameSet) {
			continue
		}
		if t == dns.TypeCNAME && slices.ContainsFunc(originals, func(o dns.RR) bool {
			return dns.RRToType(o) == dns.TypeDNAME && below(o.Header().Name, owner)
		}) {
			continue
		}
		k := forced
		if k == nil {
			if k = s.keyFor(owner, t, cuts); k == nil {
				continue
			}
			// A hand-written RRSIG still says this address serves the zone; a
			// forgery (SIGN_AS) says nothing.
			if !slices.Contains(s.served[addr], k) {
				s.served[addr] = append(s.served[addr], k)
			}
		}
		// A reserved algorithm (RFC 6014 §4) is stuffing, not a signature.
		if slices.ContainsFunc(originals, func(o dns.RR) bool {
			sig, ok := o.(*dns.RRSIG)
			return ok && strings.EqualFold(sig.Hdr.Name, owner) && sig.TypeCovered == t && (sig.Algorithm < 123 || sig.Algorithm > 251)
		}) {
			continue
		}
		w := ""
		if s.expands(wildcard, owner, k, forced) {
			w = wildcard
		}
		var set []dns.RR
		for _, rr := range originals {
			if sameSet(rr) {
				set = append(set, rr)
			}
		}
		sig, err := s.sign(k, set, w)
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, nil
}

func below(parent, name string) bool {
	return dnsutil.IsBelow(parent, name) && !strings.EqualFold(parent, name)
}

func (s *signer) keyFor(owner string, t uint16, cuts []string) *key {
	atCut := slices.ContainsFunc(cuts, func(c string) bool { return strings.EqualFold(c, owner) })
	if t == dns.TypeDS || t == dns.TypeNSEC && atCut {
		return s.deepest(owner, true)
	}
	if slices.ContainsFunc(cuts, func(c string) bool { return dnsutil.IsBelow(c, owner) }) {
		return nil
	}
	return s.deepest(owner, false)
}

func (s *signer) expands(wildcard, owner string, k, forced *key) bool {
	if wildcard == "" {
		return false
	}
	parent := cmp.Or(wildcard[2:], ".")
	return below(parent, owner) && (forced != nil || k == s.deepest(wildcard, false))
}

func (s *signer) deepest(owner string, strictlyAbove bool) *key {
	var best *key
	for _, k := range s.keys {
		if !dnsutil.IsBelow(k.zone, owner) || strictlyAbove && strings.EqualFold(k.zone, owner) {
			continue
		}
		if best == nil || dnsutil.Labels(k.zone) > dnsutil.Labels(best.zone) {
			best = k
		}
	}
	return best
}

func (s *signer) named(zone string) *key {
	for _, k := range s.keys {
		if strings.EqualFold(k.zone, zone) {
			return k
		}
	}
	return nil
}

func (s *signer) sign(k *key, set []dns.RR, wildcard string) (dns.RR, error) {
	// Signing lowercases and sorts what it is given; a wildcard owner sets
	// the labels field.
	rrs := make([]dns.RR, len(set))
	for i, rr := range set {
		rrs[i] = rr.Clone()
		if wildcard != "" {
			rrs[i].Header().Name = wildcard
		}
	}
	sig := dns.NewRRSIG(k.zone, dns.ECDSAP256SHA256, k.dnskey.KeyTag(), s.inception, s.expiration)
	if err := sig.Sign(k.priv, rrs, &dns.SignOption{}); err != nil {
		return nil, err
	}
	sig.Hdr.Name = set[0].Header().Name
	return sig, nil
}

func (s *signer) dnskey(addr netip.Addr, q dns.RR) []dns.RR {
	if s == nil || dns.RRToType(q) != dns.TypeDNSKEY {
		return nil
	}
	for _, k := range s.served[addr] {
		if strings.EqualFold(k.zone, q.Header().Name) {
			return k.answer
		}
	}
	return nil
}
