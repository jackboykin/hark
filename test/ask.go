//go:build ignore

// Ask is bench/live's client: every name to every port on 127.0.0.1 at
// once, paced open-loop, one JSON line per name.
//
//	go run ask.go <names> <rate/s> <out.jsonl> <port>...
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const timeout = 15 * time.Second

var client = &dns.Client{Transport: &dns.Transport{Dialer: &net.Dialer{Timeout: timeout}, ReadTimeout: timeout, WriteTimeout: timeout}}

// [rcode, ad, ede, answers, ms]
func ask(addr, name string) []any {
	t := time.Now()
	ms := func() int64 { return time.Since(t).Round(time.Millisecond).Milliseconds() }
	m := dns.NewMsg(name, dns.TypeA)
	m.UDPSize, m.Security = 1232, true
	r, _, err := client.Exchange(context.Background(), m, "udp", addr)
	if err == nil && r.Truncated {
		r, _, err = client.Exchange(context.Background(), m, "tcp", addr)
	}
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return []any{"TIMEOUT", false, []uint16{}, []string{}, ms()}
	case err != nil:
		return []any{fmt.Sprintf("ERROR %T", err), false, []uint16{}, []string{}, ms()}
	}
	ede := []uint16{}
	for _, o := range r.Pseudo {
		if e, ok := o.(*dns.EDE); ok {
			ede = append(ede, e.InfoCode)
		}
	}
	ans := []string{}
	for _, rr := range r.Answer {
		if t := dns.RRToType(rr); t != dns.TypeRRSIG {
			ans = append(ans, strings.ToLower(rr.Header().Name)+"|"+dnsutil.TypeToString(t)+"|"+strings.ToLower(rr.Data().String()))
		}
	}
	slices.Sort(ede)
	slices.Sort(ans)
	return []any{dnsutil.RcodeToString(r.Rcode), r.AuthenticatedData, ede, ans, ms()}
}

func main() {
	if len(os.Args) < 5 {
		log.Fatal("usage: ask <names> <rate/s> <out.jsonl> <port>...")
	}
	text, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	names := strings.Fields(string(text))
	rate, err := strconv.ParseFloat(os.Args[2], 64)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	var addrs []string
	for _, p := range os.Args[4:] {
		addrs = append(addrs, net.JoinHostPort("127.0.0.1", p))
	}

	out := bufio.NewWriter(f)
	enc := json.NewEncoder(out)
	var mu sync.Mutex
	var all sync.WaitGroup
	done := 0
	t0 := time.Now()
	for i, name := range names {
		time.Sleep(time.Until(t0.Add(time.Duration(float64(i) / rate * float64(time.Second)))))
		all.Go(func() {
			rs := make([][]any, len(addrs))
			var each sync.WaitGroup
			for j, a := range addrs {
				each.Go(func() { rs[j] = ask(a, name) })
			}
			each.Wait()
			mu.Lock()
			defer mu.Unlock()
			if err := enc.Encode(map[string]any{"n": name, "r": rs}); err != nil {
				log.Fatal(err)
			}
			done++
		})
		if i > 0 && i%10000 == 0 {
			mu.Lock()
			log.Printf("sent %d done %d in flight %d", i, done, i+1-done)
			mu.Unlock()
		}
	}
	all.Wait()
	if err := out.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
