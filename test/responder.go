package harness

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type responder struct {
	sc     *scenario
	signer *signer
	port   uint16
	step   atomic.Int64
	addrs  []netip.Addr
	udp    []*net.UDPConn
	tcp    []*net.TCPListener
	mu     sync.Mutex
	log    []query
	wg     sync.WaitGroup
}

type query struct {
	at     int64
	addr   netip.Addr
	qname  string
	qtype  uint16
	qclass uint16
}

func (q query) String() string {
	return fmt.Sprintf("%s <- %s %s", q.addr, q.qname, dnsutil.TypeToString(q.qtype))
}

func listen(ctx context.Context, sc *scenario, sg *signer) (*responder, error) {
	r := &responder{sc: sc, signer: sg}
	for _, rg := range sc.ranges {
		if !slices.Contains(r.addrs, rg.addr) {
			r.addrs = append(r.addrs, rg.addr)
		}
	}
	var err error
	if r.udp, r.tcp, err = r.bind(r.addrs); err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() {
		for i := range r.addrs {
			r.udp[i].Close()
			r.tcp[i].Close()
		}
	})
	return r, nil
}

func (r *responder) serve(ctx context.Context) {
	for i, a := range r.addrs {
		r.wg.Go(func() { r.serveUDP(a, r.udp[i]) })
		r.wg.Go(func() {
			for {
				c, err := r.tcp[i].Accept()
				if err != nil {
					return
				}
				r.wg.Go(func() { r.serveTCP(ctx, a, c) })
			}
		})
	}
}

// One port for every address: hark has one upstream-port.
func (r *responder) bind(addrs []netip.Addr) ([]*net.UDPConn, []*net.TCPListener, error) {
	for {
		var udp []*net.UDPConn
		var tcp []*net.TCPListener
		var err error
		r.port = 0
		for _, a := range addrs {
			var u *net.UDPConn
			var l *net.TCPListener
			var pc net.PacketConn
			if pc, err = stamped.ListenPacket(context.Background(), "udp", netip.AddrPortFrom(a, r.port).String()); err != nil {
				break
			}
			u = pc.(*net.UDPConn)
			udp = append(udp, u)
			r.port = uint16(u.LocalAddr().(*net.UDPAddr).Port)
			if l, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, r.port))); err != nil {
				break
			}
			tcp = append(tcp, l)
		}
		if err == nil {
			return udp, tcp, nil
		}
		for _, c := range udp {
			c.Close()
		}
		for _, l := range tcp {
			l.Close()
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, err
		}
	}
}

// Over loopback the kernel stamps a datagram inside hark's sendmsg, so the
// stamps keep hark's send order across addresses; the readers do not.
var stamped = net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}}

// A timespec: two 64-bit words on 64-bit Linux.
func stamp(oob []byte) int64 {
	msgs, _ := syscall.ParseSocketControlMessage(oob)
	for _, m := range msgs {
		if m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_TIMESTAMPNS && len(m.Data) >= 16 {
			return int64(binary.NativeEndian.Uint64(m.Data))*1e9 + int64(binary.NativeEndian.Uint64(m.Data[8:]))
		}
	}
	panic("SO_TIMESTAMPNS is set, yet a datagram came without a stamp")
}

func (r *responder) serveUDP(addr netip.Addr, c *net.UDPConn) {
	buf, oob := make([]byte, 65535), make([]byte, 64)
	for {
		n, oobn, _, from, err := c.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return
		}
		q := &dns.Msg{Data: slices.Clone(buf[:n])}
		if q.Unpack() != nil || len(q.Question) == 0 {
			continue
		}
		r.receive(stamp(oob[:oobn]), addr, q)
		if m := r.reply(addr, q, false); m != nil {
			if wire := truncate(q, m); wire != nil {
				c.WriteToUDPAddrPort(wire, from)
			}
		}
	}
}

func (r *responder) serveTCP(ctx context.Context, addr netip.Addr, c net.Conn) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer func() { stop(); c.Close() }()
	for {
		q, err := readFrame(c)
		if err != nil || len(q.Question) == 0 {
			return
		}
		// Stamped when read: a TCP query can only sort late.
		r.receive(time.Now().UnixNano(), addr, q)
		m := r.reply(addr, q, true)
		if m == nil {
			continue
		}
		wire, err := frame(m)
		if err != nil {
			continue
		}
		if _, err := c.Write(wire); err != nil {
			return
		}
	}
}

func frame(m *dns.Msg) ([]byte, error) {
	if err := m.Pack(); err != nil {
		return nil, err
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(m.Data))), m.Data...), nil
}

func readFrame(c io.Reader) (*dns.Msg, error) {
	var n uint16
	if err := binary.Read(c, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	m := &dns.Msg{Data: make([]byte, n)}
	if _, err := io.ReadFull(c, m.Data); err != nil {
		return nil, err
	}
	return m, m.Unpack()
}

func (r *responder) receive(at int64, addr netip.Addr, q *dns.Msg) {
	h := q.Question[0].Header()
	t := dns.RRToType(q.Question[0])
	// Scenarios don't count root priming (RFC 8109).
	if h.Name == "." && t == dns.TypeNS {
		return
	}
	r.mu.Lock()
	i := len(r.log)
	for i > 0 && r.log[i-1].at > at {
		i--
	}
	r.log = slices.Insert(r.log, i, query{at, addr, strings.ToLower(h.Name), t, h.Class})
	r.mu.Unlock()
}

func (r *responder) queries() []query {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.log)
}

// The question goes back case and all, for hark's 0x20 check; DO too (RFC
// 3225 §3).
func replyTo(q *dns.Msg) *dns.Msg {
	m := &dns.Msg{Question: q.Question}
	m.ID, m.Opcode, m.RecursionDesired, m.Response = q.ID, q.Opcode, q.RecursionDesired, true
	if q.UDPSize > 0 {
		m.UDPSize, m.Security = payload, q.Security
	}
	return m
}

func (r *responder) reply(addr netip.Addr, q *dns.Msg, tcp bool) *dns.Msg {
	m := replyTo(q)
	e := r.find(addr, q, tcp)
	if e == nil {
		// REFUSED, so a coverage gap shows instead of a blackhole.
		if rrs := r.signer.dnskey(addr, q.Question[0]); rrs != nil {
			m.Authoritative, m.Answer = true, rrs
		} else {
			m.Rcode = dns.RcodeRefused
		}
		return m
	}
	if e.adjust["drop"] {
		return nil
	}
	h := e.reply
	m.Authoritative, m.Truncated, m.RecursionAvailable = h.Authoritative, h.Truncated, h.RecursionAvailable
	m.AuthenticatedData, m.CheckingDisabled, m.Rcode = h.AuthenticatedData, h.CheckingDisabled, h.Rcode
	switch {
	case e.adjust["drop_question"]:
		m.Question = nil
	case e.adjust["force_upper_qname"]:
		c := q.Question[0].Clone()
		c.Header().Name = strings.ToUpper(c.Header().Name)
		m.Question = []dns.RR{c}
	}
	m.Answer, m.Ns, m.Extra = e.answer, e.authority, e.extra
	return m
}

func truncate(q, m *dns.Msg) []byte {
	if m.Pack() != nil {
		return nil
	}
	if len(m.Data) <= max(int(q.UDPSize), dns.MinMsgSize) {
		return m.Data
	}
	t := &dns.Msg{MsgHeader: m.MsgHeader, Question: m.Question}
	t.Truncated = true
	if t.Pack() != nil {
		return nil
	}
	return t.Data
}

func (r *responder) find(addr netip.Addr, q *dns.Msg, tcp bool) *entry {
	at := int(r.step.Load())
	for _, rg := range r.sc.ranges {
		if rg.addr != addr || at < rg.start || at > rg.end {
			continue
		}
		for _, e := range rg.entries {
			if e.answers(q, tcp) {
				return e
			}
		}
	}
	return nil
}

func (e *entry) answers(q *dns.Msg, tcp bool) bool {
	if len(e.question) == 0 {
		return false
	}
	m := e.match
	question := len(m) == 0 || m["question"]
	eq, qq := e.question[0], q.Question[0]
	switch {
	case m["tcp"] && !tcp, m["udp"] && tcp,
		m["opcode"] && e.reply.Opcode != q.Opcode,
		(question || m["qclass"]) && eq.Header().Class != qq.Header().Class,
		(question || m["qtype"]) && dns.RRToType(eq) != dns.RRToType(qq),
		(question || m["qname"]) && !strings.EqualFold(eq.Header().Name, qq.Header().Name),
		m["subdomain"] && !dnsutil.IsBelow(eq.Header().Name, qq.Header().Name):
		return false
	}
	return true
}
