package harness

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

const twoSilent = `; hark: root-hints = 127.0.10.1
; hark: qname-minimisation = no

SCENARIO_BEGIN two silent authorities outlast a stub
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ENTRY_BEGIN
    MATCH opcode subdomain
    ADJUST copy_id copy_query
    REPLY QR NOERROR
    SECTION QUESTION
      example.com. IN A
    SECTION AUTHORITY
      example.com. 86400 IN NS ns1.example.com.
      example.com. 86400 IN NS ns2.example.com.
    SECTION ADDITIONAL
      ns1.example.com. 86400 IN A 127.0.10.3
      ns2.example.com. 86400 IN A 127.0.10.4
  ENTRY_END
RANGE_END
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.3
  ENTRY_BEGIN
    MATCH opcode
    ADJUST drop
    REPLY QR AA NOERROR
    SECTION QUESTION
      example.com. IN A
  ENTRY_END
RANGE_END
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.4
  ENTRY_BEGIN
    MATCH opcode
    ADJUST drop
    REPLY QR AA NOERROR
    SECTION QUESTION
      example.com. IN A
  ENTRY_END
RANGE_END
SCENARIO_END
`

func TestLateUDPIsSilentAndTCPIsAnswered(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, twoSilent, nil)
	udp := make(chan error, 1)
	go func() {
		_, err := ask(t.Context(), "udp", h.addr, "b.example.com.", 4500*time.Millisecond)
		udp <- err
	}()
	t0 := time.Now()
	r, err := ask(t.Context(), "tcp", h.addr, "a.example.com.", 4500*time.Millisecond)
	took := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeServerFailure {
		t.Errorf("TCP: want SERVFAIL, got:\n%v", r)
	}
	if took <= 2*time.Second || took >= 4*time.Second {
		t.Fatalf("TCP answered in %v: the test needs a reply due past 2 s and inside the UDP wait", took)
	}
	if err := <-udp; !timedOut(err) {
		t.Errorf("UDP: want no reply, got %v", err)
	}

	t0 = time.Now()
	wantRcode(t, h.addr, "b.example.com.", dns.RcodeServerFailure, 2*time.Second)
	if d := time.Since(t0); d >= 500*time.Millisecond {
		t.Errorf("the remembered failure took %v", d)
	}
}
