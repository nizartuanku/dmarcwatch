package dmarcwatch

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nizartuanku/dmarcwatch/core"
	"github.com/nizartuanku/dmarcwatch/dmarcrep"
)

var testNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func newTestCollector(s Store) *Collector {
	c := New(s)
	c.now = func() time.Time { return testNow }
	return c
}

// rep builds a one-source report ending `age` before testNow.
func rep(domain, org, id string, age time.Duration, ip string, count int, dkim, spf, policy string) dmarcrep.Report {
	end := testNow.Add(-age)
	return dmarcrep.Report{
		Org: org, ReportID: id, Domain: domain, Policy: policy, Pct: 100,
		Begin: end.Add(-24 * time.Hour), End: end,
		Records: []dmarcrep.Record{{SourceIP: ip, Count: count, EvalDKIM: dkim, EvalSPF: spf, HeaderFrom: domain}},
	}
}

func mustPut(t *testing.T, s Store, r dmarcrep.Report) {
	t.Helper()
	if _, err := s.PutReport(r); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, c *Collector, domain string) map[string]core.Finding {
	t.Helper()
	fs, err := c.Collect(context.Background(), core.Target{Raw: domain, Canonical: domain})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Finding{}
	for _, f := range fs {
		out[f.Check+"|"+fmt.Sprint(f.Evidence["source_ip"])] = f
		out[f.Check] = f
	}
	for _, f := range fs {
		if err := f.ValidateForIngest(); err != nil {
			t.Errorf("finding %s invalid: %v", f.Check, err)
		}
	}
	return out
}

func TestValidateTarget(t *testing.T) {
	c := newTestCollector(NewMemStore())
	for raw, want := range map[string]string{
		"Example.COM":        "example.com",
		" https://mail.co. ": "mail.co",
		"user@corp.example":  "corp.example",
	} {
		tgt, err := c.ValidateTarget(raw)
		if err != nil || tgt.Canonical != want {
			t.Errorf("%q → %q (%v), want %q", raw, tgt.Canonical, err, want)
		}
	}
	for _, bad := range []string{"", "nodot", "two words.com", "a/b.com"} {
		if _, err := c.ValidateTarget(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestNoDataFinding(t *testing.T) {
	c := newTestCollector(NewMemStore())
	fs := collect(t, c, "example.com")
	if _, ok := fs["dmarc.no-data"]; !ok || len(fs) < 1 {
		t.Fatalf("want no-data finding, got %v", keys(fs))
	}
}

func TestSpoofingFinding(t *testing.T) {
	s := NewMemStore()
	// Legit history so the domain has data, plus a high-volume fail-both source.
	mustPut(t, s, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 500, "pass", "pass", "none"))
	mustPut(t, s, rep("example.com", "google.com", "g2", 2*24*time.Hour, "198.51.100.7", 40, "fail", "fail", "none"))
	fs := collect(t, newTestCollector(s), "example.com")
	f, ok := fs["dmarc.spoofing|198.51.100.7"]
	if !ok {
		t.Fatalf("want spoofing finding, got %v", keys(fs))
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity: %s", f.Severity)
	}
	// The aligned source must NOT be called spoofing.
	if _, bad := fs["dmarc.spoofing|203.0.113.10"]; bad {
		t.Error("aligned source flagged as spoofing")
	}
}

func TestSpoofingNeedsVolume(t *testing.T) {
	s := NewMemStore()
	mustPut(t, s, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 500, "pass", "pass", "none"))
	mustPut(t, s, rep("example.com", "google.com", "g2", 2*24*time.Hour, "198.51.100.9", 3, "fail", "fail", "none")) // below threshold
	fs := collect(t, newTestCollector(s), "example.com")
	if _, bad := fs["dmarc.spoofing|198.51.100.9"]; bad {
		t.Error("low-volume failures should not raise spoofing")
	}
}

func TestNewSourceFinding(t *testing.T) {
	s := NewMemStore()
	// 20 days of history from one source, then a new aligned source 2 days ago.
	mustPut(t, s, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 500, "pass", "pass", "none"))
	mustPut(t, s, rep("example.com", "google.com", "g2", 2*24*time.Hour, "192.0.2.55", 25, "pass", "pass", "none"))
	fs := collect(t, newTestCollector(s), "example.com")
	if _, ok := fs["dmarc.new-source|192.0.2.55"]; !ok {
		t.Fatalf("want new-source finding, got %v", keys(fs))
	}
	if _, bad := fs["dmarc.new-source|203.0.113.10"]; bad {
		t.Error("old source flagged as new")
	}
}

func TestNewSourceRequiresHistory(t *testing.T) {
	s := NewMemStore()
	// Domain only 3 days old: EVERY source is "new" — so none should be flagged.
	mustPut(t, s, rep("example.com", "google.com", "g1", 3*24*time.Hour, "203.0.113.10", 100, "pass", "pass", "none"))
	fs := collect(t, newTestCollector(s), "example.com")
	if _, bad := fs["dmarc.new-source|203.0.113.10"]; bad {
		t.Error("new-source raised without enough domain history")
	}
}

func TestPolicyProgress(t *testing.T) {
	// p=none, high volume, 2 orgs, all aligned → ready to tighten.
	s := NewMemStore()
	mustPut(t, s, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 300, "pass", "pass", "none"))
	mustPut(t, s, rep("example.com", "outlook.com", "o1", 10*24*time.Hour, "203.0.113.10", 300, "pass", "pass", "none"))
	fs := collect(t, newTestCollector(s), "example.com")
	f, ok := fs["dmarc.policy"]
	if !ok {
		t.Fatalf("want policy finding, got %v", keys(fs))
	}
	if f.Evidence["ready_to_tighten"] != true {
		t.Errorf("should be ready: %+v", f.Evidence)
	}

	// p=quarantine and ready → info-level "ready for reject".
	s2 := NewMemStore()
	mustPut(t, s2, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 300, "pass", "pass", "quarantine"))
	mustPut(t, s2, rep("example.com", "outlook.com", "o1", 10*24*time.Hour, "203.0.113.10", 300, "pass", "pass", "quarantine"))
	fs2 := collect(t, newTestCollector(s2), "example.com")
	f2, ok := fs2["dmarc.policy"]
	if !ok || f2.Severity != core.SeverityInfo {
		t.Fatalf("want info-level reject-readiness, got %v", keys(fs2))
	}

	// p=reject → no policy finding at all.
	s3 := NewMemStore()
	mustPut(t, s3, rep("example.com", "google.com", "g1", 2*24*time.Hour, "203.0.113.10", 300, "pass", "pass", "reject"))
	fs3 := collect(t, newTestCollector(s3), "example.com")
	if _, bad := fs3["dmarc.policy"]; bad {
		t.Error("p=reject should not raise a policy finding")
	}
}

func TestNoReportsFinding(t *testing.T) {
	s := NewMemStore()
	mustPut(t, s, rep("example.com", "google.com", "g1", 10*24*time.Hour, "203.0.113.10", 100, "pass", "pass", "none"))
	fs := collect(t, newTestCollector(s), "example.com")
	if _, ok := fs["dmarc.no-reports"]; !ok {
		t.Fatalf("want no-reports after 10 silent days, got %v", keys(fs))
	}

	s2 := NewMemStore()
	mustPut(t, s2, rep("example.com", "google.com", "g1", 24*time.Hour, "203.0.113.10", 100, "pass", "pass", "none"))
	fs2 := collect(t, newTestCollector(s2), "example.com")
	if _, bad := fs2["dmarc.no-reports"]; bad {
		t.Error("fresh reports should not raise no-reports")
	}
}

func TestAlignmentDrop(t *testing.T) {
	s := NewMemStore()
	// Month: 1000 aligned. This week: 60 of 120 aligned (50% vs ~93%).
	mustPut(t, s, rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 1000, "pass", "pass", "reject"))
	mustPut(t, s, rep("example.com", "google.com", "g2", 2*24*time.Hour, "203.0.113.10", 60, "pass", "pass", "reject"))
	mustPut(t, s, rep("example.com", "google.com", "g3", 2*24*time.Hour, "203.0.113.99", 60, "fail", "fail", "reject"))
	fs := collect(t, newTestCollector(s), "example.com")
	if _, ok := fs["dmarc.alignment-drop"]; !ok {
		t.Fatalf("want alignment-drop, got %v", keys(fs))
	}
}

func TestDuplicateReportIgnored(t *testing.T) {
	s := NewMemStore()
	r := rep("example.com", "google.com", "same-id", 24*time.Hour, "203.0.113.10", 10, "pass", "pass", "none")
	if stored, _ := s.PutReport(r); !stored {
		t.Fatal("first put should store")
	}
	if stored, _ := s.PutReport(r); stored {
		t.Fatal("second put should be a duplicate")
	}
}

// TestSQLiteOverviewMatchesMem feeds identical reports to both stores and
// compares the Overview both compute — the contract test that keeps the test
// store honest.
func TestSQLiteOverviewMatchesMem(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sq, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	mem := NewMemStore()

	reports := []dmarcrep.Report{
		rep("example.com", "google.com", "g1", 20*24*time.Hour, "203.0.113.10", 500, "pass", "pass", "none"),
		rep("example.com", "outlook.com", "o1", 5*24*time.Hour, "203.0.113.10", 100, "pass", "fail", "none"),
		rep("example.com", "google.com", "g2", 2*24*time.Hour, "198.51.100.7", 40, "fail", "fail", "none"),
		rep("other.org", "google.com", "x1", 2*24*time.Hour, "192.0.2.1", 9, "pass", "pass", "reject"),
	}
	for _, r := range reports {
		mustPut(t, sq, r)
		mustPut(t, mem, r)
	}

	a, err := sq.Overview("example.com", testNow)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mem.Overview("example.com", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if a.Msgs30 != b.Msgs30 || a.Aligned30 != b.Aligned30 || a.Msgs7 != b.Msgs7 ||
		a.Aligned7 != b.Aligned7 || a.Orgs30 != b.Orgs30 || a.Policy != b.Policy ||
		len(a.Sources) != len(b.Sources) || !a.LastEnd.Equal(b.LastEnd) {
		t.Fatalf("stores disagree:\nsqlite: %+v\nmem:    %+v", a, b)
	}
	if a.Msgs30 != 640 || a.Aligned30 != 600 || a.Orgs30 != 2 {
		t.Errorf("aggregates wrong: %+v", a)
	}
}

func keys(m map[string]core.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
