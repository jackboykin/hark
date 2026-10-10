package harness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func build() (string, error) {
	prefix, err := filepath.Abs("../zig-out/harness")
	if err != nil {
		return "", err
	}
	args := slices.Concat([]string{"build", "-Dtesting=true"}, strings.Fields(os.Getenv("HARK_BUILD_ARGS")), []string{"-p", prefix})
	cmd := exec.Command("zig", args...)
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("zig %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return filepath.Join(prefix, "bin", "hark"), nil
}

type hark struct {
	addr    netip.AddrPort
	cmd     *exec.Cmd
	logPath string
	done    chan struct{}
}

func startHark(ctx context.Context, t *testing.T, bin string, sc *scenario, port uint16, anchor string) (*hark, error) {
	// Without hints, hark asks the real root servers.
	if len(sc.rootHints) == 0 {
		return nil, errors.New("no root hints: declare `; hark: root-hints = <ip>[, ...]`")
	}
	dir := t.ArtifactDir()
	for {
		listen, err := freePort()
		if err != nil {
			return nil, err
		}
		h := &hark{addr: listen, logPath: filepath.Join(dir, "hark.log"), done: make(chan struct{})}
		cfg := filepath.Join(dir, "hark.toml")
		if err := os.WriteFile(cfg, []byte(sc.config.toml(listen, port, sc.rootHints, anchor)), 0o644); err != nil {
			return nil, err
		}
		if err := h.start(ctx, bin, cfg, sc.config.nofile); err != nil {
			return nil, err
		}
		err = h.ready()
		if err != nil && h.exited() && strings.Contains(h.log(), "AddressInUse") {
			handed.Delete(listen)
			continue
		}
		t.Cleanup(func() { h.stopped(t); handed.Delete(listen) })
		return h, err
	}
}

// A Debug build reports leaks at exit without touching the status.
var allocatorError = regexp.MustCompile(`error\(\w*Allocator\)`)

func (h *hark) stopped(t *testing.T) {
	<-h.done
	if !h.cmd.ProcessState.Success() {
		t.Errorf("hark did not exit cleanly on SIGTERM: %v", h.cmd.ProcessState)
	}
	log := h.log()
	if at := allocatorError.FindStringIndex(log); at != nil {
		t.Errorf("hark's allocator complained at exit:\n%s", log[at[0]:])
	}
}

func (h *hark) start(ctx context.Context, bin, cfg string, nofile int) error {
	log, err := os.Create(h.logPath)
	if err != nil {
		return err
	}
	defer log.Close()
	args := []string{bin, "serve", "--config", cfg, "--verbose"}
	if nofile > 0 {
		args = append([]string{"sh", "-c", fmt.Sprintf(`ulimit -n %d && exec "$0" "$@"`, nofile)}, args...)
	}
	h.cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	h.cmd.Stdout, h.cmd.Stderr = log, log
	// Pdeathsig follows the forking thread, and the runtime retires a thread
	// only when a goroutine locked to it exits; nothing here locks one.
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	h.cmd.Cancel = func() error { return h.cmd.Process.Signal(syscall.SIGTERM) }
	h.cmd.WaitDelay = 2 * time.Second
	if err := h.cmd.Start(); err != nil {
		return err
	}
	go func() {
		h.cmd.Wait()
		close(h.done)
	}()
	return nil
}

// A probe of the port could reach another test's freePort before hark
// binds.
func (h *hark) ready() error {
	said := "listening on " + h.addr.String()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if h.exited() {
			return fmt.Errorf("hark exited early (%v); log:\n%s", h.cmd.ProcessState, h.log())
		}
		if strings.Contains(h.log(), said) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("hark not ready within 5s; log:\n%s", h.log())
}

func (h *hark) exited() bool {
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

func (h *hark) log() string {
	b, _ := os.ReadFile(h.logPath)
	return string(b)
}

// hark binds UDP with SO_REUSEADDR: a second hark on a port the kernel
// offered again would take the first's queries.
var handed sync.Map

func freePort() (netip.AddrPort, error) {
	for {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return netip.AddrPort{}, err
		}
		ap := u.LocalAddr().(*net.UDPAddr).AddrPort()
		l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(ap))
		u.Close()
		if err == nil {
			l.Close()
			if _, dup := handed.LoadOrStore(ap, nil); !dup {
				return ap, nil
			}
			continue
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return netip.AddrPort{}, err
		}
	}
}

func (c *config) toml(listen netip.AddrPort, port uint16, hints []netip.Addr, anchor string) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	list := func(ss []string) string {
		q := make([]string, len(ss))
		for i, s := range ss {
			q[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(q, ", ") + "]"
	}
	line("[server]")
	line("listen = %s", list([]string{listen.String()}))
	line("minimal-responses = %t", c.minimalResponses)
	if c.tcpIdleMs > 0 {
		line("tcp-idle-timeout-ms = %d", c.tcpIdleMs)
	}
	if len(c.allowFrom) > 0 {
		line("allow-from = %s", list(c.allowFrom))
	}
	line("\n[resolver]")
	line("qname-minimization = %t", c.qnameMinimization)
	line("dnssec = %t", anchor != "")
	line("upstream-port = %d", port)
	line("allow-loopback-upstreams = true")
	if c.staggerMs != nil {
		line("stagger-ms = %d", *c.staggerMs)
	}
	if c.maxQueries != nil {
		line("max-queries = %d", *c.maxQueries)
	}
	if c.dns64Prefix != "" {
		line("dns64-prefix = %q", c.dns64Prefix)
	}
	var hs []string
	for _, a := range hints {
		hs = append(hs, netip.AddrPortFrom(a, port).String())
	}
	line("root-hints = %s", list(hs))
	var zs []string
	for _, z := range c.stubZones {
		e := z.zone
		for _, a := range z.servers {
			e += " " + netip.AddrPortFrom(a, port).String()
		}
		zs = append(zs, e)
	}
	line("stub-zones = %s", list(zs))
	if anchor != "" {
		// A rollover in flight: KSK-2017 heads the set and signs nothing
		// here, so every signed scenario rests on the anchor after it.
		const ksk2017 = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
		line("trust-anchors = %s", list([]string{ksk2017, anchor}))
	}
	line("\n[cache]")
	line("min-ttl = %d", c.minTTL)
	if c.cacheSize > 0 {
		line("size = %d", c.cacheSize)
	}
	line("serve-stale-ttl = %d", c.serveStaleTTL)
	line("prefetch = %t", c.prefetch)
	line("\n[rebinding]")
	line("enabled = %t", c.rebinding)
	line("allow-zones = %s", list(c.allowZones))
	line("extra-allow = %s", list(c.extraAllow))
	return b.String()
}
