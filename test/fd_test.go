package harness

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/sys/unix"
)

const oneAuthority = `; hark: root-hints = 127.0.10.1

SCENARIO_BEGIN one authority for everything
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ENTRY_BEGIN
    MATCH opcode
    ADJUST copy_id copy_query
    REPLY QR AA NOERROR
    SECTION QUESTION
      example.com. IN A
    SECTION ANSWER
      example.com. 60 IN A 192.0.2.1
  ENTRY_END
RANGE_END
SCENARIO_END
`

func lowestFreeFD(t *testing.T, pid int) int {
	t.Helper()
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for _, fd := range fds {
		n, _ := strconv.Atoi(fd.Name())
		used[n] = true
	}
	n := 0
	for used[n] {
		n++
	}
	return n
}

func TestFDExhaustionIsUnsentNotATimeout(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, oneAuthority, nil)
	pid := h.cmd.Process.Pid
	wantRcode(t, h.addr, "a.example.com.", dns.RcodeSuccess, 5*time.Second)
	var before unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &before); err != nil {
		t.Fatal(err)
	}
	low := unix.Rlimit{Cur: uint64(lowestFreeFD(t, pid)), Max: before.Max}
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &low, nil); err != nil {
		t.Fatal(err)
	}
	wantRcode(t, h.addr, "b.example.com.", dns.RcodeServerFailure, 5*time.Second)
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &before, nil); err != nil {
		t.Fatal(err)
	}
	wantRcode(t, h.addr, "b.example.com.", dns.RcodeSuccess, 5*time.Second)

	s := stats(t, h, "stats resolver", "unsent", "timeout")
	if unsent, timeout := s[0], s[1]; unsent < 1 || timeout != 0 {
		t.Errorf("unsent %d timeout %d, want unsent at least 1 and no timeout", unsent, timeout)
	}
}
