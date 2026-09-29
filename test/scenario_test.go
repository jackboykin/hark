package harness

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

var harkBin string

// Built outside every test's deadline: a cold zig cache takes a while.
func TestMain(m *testing.M) {
	var err error
	if harkBin, err = build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

var simOnly = regexp.MustCompile(`(?m)^; sim-only: (.+)$`)

func TestScenarios(t *testing.T) {
	root := "scenarios"
	err := fs.WalkDir(os.DirFS(root), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".rpl" {
			return err
		}
		t.Run(strings.TrimSuffix(path, ".rpl"), func(t *testing.T) {
			t.Parallel()
			text, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			if m := simOnly.FindSubmatch(text); m != nil {
				t.Skip(string(m[1]))
			}
			sc, err := parse(path, text)
			if err != nil {
				t.Fatal(err)
			}
			run(t, sc)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, sc *scenario) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	resp, h := launch(ctx, t, sc)

	fail := func(s *step, format string, args ...any) {
		t.Helper()
		var b strings.Builder
		for i, q := range resp.queries() {
			fmt.Fprintf(&b, "  [%d] %v\n", i, q)
		}
		t.Fatalf("step %d: %s\n---- responder log:\n%s---- hark log:\n%s", s.n, fmt.Sprintf(format, args...), b.String(), h.log())
	}

	var last *dns.Msg
	cursor := 0
	for _, s := range sc.steps {
		if ctx.Err() != nil {
			fail(s, "scenario deadline passed")
		}
		if h.exited() {
			fail(s, "hark died mid-scenario")
		}
		resp.step.Store(int64(s.n))
		switch s.kind {
		case "QUERY":
			r, err := askEntry(ctx, h.addr, s.entry, sc.clientTimeout)
			if err != nil {
				fail(s, "QUERY: %v", err)
			}
			last = r
		case "CHECK_ANSWER":
			if last == nil {
				fail(s, "CHECK_ANSWER before any QUERY")
			}
			if err := checkAnswer(last, s.entry); err != nil {
				fail(s, "%v", err)
			}
		case "CHECK_QUERY_LOG":
			if err := checkQueryLog(resp.queries(), s.entry); err != nil {
				fail(s, "%v", err)
			}
		case "CHECK_MAX_QUERIES":
			if n := len(resp.queries()); n > s.max {
				fail(s, "CHECK_MAX_QUERIES: hark sent %d upstream queries, bound is %d", n, s.max)
			}
		case "CHECK_OUT_QUERY":
			// A query to another address may still be on its way into the
			// log and sort before the cursor; no scenario sends one
			// unawaited.
			log := resp.queries()
			for deadline := time.Now().Add(3 * time.Second); cursor >= len(log) && time.Now().Before(deadline); log = resp.queries() {
				time.Sleep(5 * time.Millisecond)
			}
			if cursor >= len(log) {
				fail(s, "CHECK_OUT_QUERY: no upstream query at log position %d; log has %d", cursor, len(log))
			}
			if err := checkOutQuery(log[cursor], s.entry); err != nil {
				fail(s, "(log position %d): %v", cursor, err)
			}
			cursor++
		case "TIME_PASSES":
			if err := advanceClock(ctx, h.addr, s.seconds); err != nil {
				fail(s, "TIME_PASSES: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func launch(ctx context.Context, t *testing.T, sc *scenario) (*responder, *hark) {
	t.Helper()
	var sg *signer
	anchor := ""
	if len(sc.zones) > 0 {
		var err error
		if sg, err = newSigner(sc.zones); err != nil {
			t.Fatal(err)
		}
		anchor = sg.anchor()
	}
	resp, err := listen(ctx, sc, sg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resp.wg.Wait)
	h, err := startHark(ctx, t, harkBin, sc, resp.port, anchor)
	if err != nil {
		t.Fatal(err)
	}
	// Signed once hark is ready, so its start spends none of a signature's
	// validity.
	if sg != nil {
		if err := sg.bake(sc.ranges, sc.sigValidity); err != nil {
			t.Fatal(err)
		}
	}
	resp.serve(ctx)
	return resp, h
}
