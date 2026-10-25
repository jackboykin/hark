package harness

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestAWildcardListenerRepliesFromTheAddressAsked(t *testing.T) {
	t.Parallel()
	_, h := launchText(t, oneAuthority, func(c *config) {
		c.listenAny = true
		c.allowFrom = []string{"127.0.0.0/8"}
	})
	asked := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), h.addr.Port())
	wantRcode(t, asked, "a.example.com.", dns.RcodeSuccess, 5*time.Second)
}
