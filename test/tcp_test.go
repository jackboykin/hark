package harness

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// hark answers .invalid itself (RFC 6761).

const idle = 1500 * time.Millisecond

// Port 9 is discard (RFC 863): nothing hark asks is answered.
func launchBare(t *testing.T, c config) *hark {
	t.Helper()
	c.qnameMinimization, c.minimalResponses = true, true
	sc := &scenario{rootHints: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, config: c}
	h, err := startHark(t.Context(), t, harkBin, sc, 9, "")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func dial(t *testing.T, h *hark) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", h.addr.String(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func framed(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	m := dns.NewMsg(name, dns.TypeA)
	m.ID = id
	f, err := frame(m)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func send(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func replies(t *testing.T, c net.Conn, count int) map[uint16]*dns.Msg {
	t.Helper()
	got := map[uint16]*dns.Msg{}
	for len(got) < count {
		m, err := readFrame(c)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[m.ID] = m
	}
	return got
}

func ids(got map[uint16]*dns.Msg) []uint16 { return slices.Sorted(maps.Keys(got)) }

func wantEOF(t *testing.T, c net.Conn) {
	t.Helper()
	if n, err := c.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("want the connection closed, read %d bytes, %v", n, err)
	}
}

func TestTCPClients(t *testing.T) {
	t.Parallel()
	h := launchBare(t, config{tcpIdleMs: int(idle / time.Millisecond)})

	t.Run("frames split across reads", func(t *testing.T) {
		t.Parallel()
		var wire []byte
		for i := range uint16(8) {
			wire = append(wire, framed(t, fmt.Sprintf("p%d.invalid.", i+1), i+1)...)
		}
		c := dial(t, h)
		for _, cut := range []int{1, 7, len(wire) - 20} {
			send(t, c, wire[:cut])
			time.Sleep(50 * time.Millisecond)
			wire = wire[cut:]
		}
		send(t, c, wire)
		got := replies(t, c, 8)
		if !slices.Equal(ids(got), []uint16{1, 2, 3, 4, 5, 6, 7, 8}) {
			t.Fatalf("replies to %v, want 1 to 8", ids(got))
		}
		for _, m := range got {
			if m.Rcode != dns.RcodeNameError {
				t.Errorf("want NXDOMAIN:\n%v", m)
			}
		}
	})

	t.Run("half close still answered", func(t *testing.T) {
		t.Parallel()
		c := dial(t, h)
		send(t, c, framed(t, "half.invalid.", 9))
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := ids(replies(t, c, 1)); !slices.Equal(got, []uint16{9}) {
			t.Fatalf("replies to %v, want 9", got)
		}
	})

	t.Run("oversized frame closes", func(t *testing.T) {
		t.Parallel()
		c := dial(t, h)
		send(t, c, append([]byte{0xff, 0xff}, make([]byte, 64)...))
		wantEOF(t, c)
	})

	t.Run("slots recycle", func(t *testing.T) {
		t.Parallel()
		for i := range uint16(200) {
			c := dial(t, h)
			send(t, c, framed(t, fmt.Sprintf("r%d.invalid.", i), i))
			if got := ids(replies(t, c, 1)); !slices.Equal(got, []uint16{i}) {
				t.Fatalf("connection %d: replies to %v", i, got)
			}
			c.Close()
		}
	})

	t.Run("many concurrent connections", func(t *testing.T) {
		t.Parallel()
		conns := make([]net.Conn, 16)
		for i := range conns {
			conns[i] = dial(t, h)
		}
		for i, c := range conns {
			send(t, c, framed(t, fmt.Sprintf("c%d.invalid.", 100+i), uint16(100+i)))
		}
		for i, c := range conns {
			if got := ids(replies(t, c, 1)); !slices.Equal(got, []uint16{uint16(100 + i)}) {
				t.Fatalf("connection %d: replies to %v", i, got)
			}
		}
	})

	t.Run("idle connection is closed", func(t *testing.T) {
		t.Parallel()
		c := dial(t, h)
		send(t, c, framed(t, "idle.invalid.", 7))
		if got := ids(replies(t, c, 1)); !slices.Equal(got, []uint16{7}) {
			t.Fatalf("replies to %v, want 7", got)
		}
		t0 := time.Now()
		wantEOF(t, c)
		if d := time.Since(t0); d < idle-200*time.Millisecond || d > idle+2*time.Second {
			t.Errorf("closed after %v, idle timeout is %v", d, idle)
		}
	})

	t.Run("dripped frame is closed at idle", func(t *testing.T) {
		t.Parallel()
		c := dial(t, h)
		send(t, c, []byte{0x02, 0x00})
		t0 := time.Now()
		buf := make([]byte, 16)
		for time.Since(t0) < idle+3*time.Second {
			if _, err := c.Write([]byte{0}); err != nil {
				break
			}
			c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if _, err := c.Read(buf); err != nil && !timedOut(err) {
				break
			}
		}
		if d := time.Since(t0); d > idle+2*time.Second {
			t.Errorf("a dripping client held on %v, idle timeout is %v", d, idle)
		}
	})
}

func TestAllowFromRefusesTCP(t *testing.T) {
	t.Parallel()
	h := launchBare(t, config{allowFrom: []string{"192.0.2.0/24"}})
	c := dial(t, h)
	send(t, c, framed(t, "acl.invalid.", 1))
	if n, err := c.Read(make([]byte, 16)); err != io.EOF && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the connection closed, read %d bytes, %v", n, err)
	}
}
