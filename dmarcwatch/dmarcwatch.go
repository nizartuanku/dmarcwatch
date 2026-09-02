// Package dmarcwatch is the seventh Sentinel product: a self-hosted DMARC
// aggregate-report (RUA) monitor. A target is one email domain. Reports arrive
// by upload (raw XML, .xml.gz, or .zip) through the console; Collect reads the
// stored rows and answers the four questions DMARC monitoring exists for:
//
//  1. Who is sending mail as this domain — and is anyone spoofing it?
//  2. Did a new sending source appear that nobody approved?
//  3. Are we ready to tighten the policy (none → quarantine → reject)?
//  4. Are reports still flowing at all?
//
// It is upload-driven and poll-affirmed: ingestion triggers an immediate
// rescan; the scheduler re-affirms findings and catches the "reports stopped
// arriving" case that only time can reveal.
package dmarcwatch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nizartuanku/dmarcwatch/core"
	"github.com/nizartuanku/dmarcwatch/dmarcrep"
)

// ModuleID is the module id (also the license product id).
const ModuleID = "dmarcwatch"

// Tunables. Fixed constants in v0 — thresholds users actually argue about can
// become per-domain settings later without changing fingerprints.
const (
	windowLong      = 30 * 24 * time.Hour // analysis window
	windowRecent    = 7 * 24 * time.Hour  // "new source" / drop window
	minHistory      = 14 * 24 * time.Hour // history required before new-source findings
	spoofMinMsgs    = 10                  // min messages failing both to call spoofing
	spoofMinFailPct = 90                  // and ≥ this % of the source's own traffic
	newSourceMin    = 5                   // min messages before a new source is worth a finding
	readyMinMsgs    = 100                 // min messages before "ready to tighten" advice
	readyMinOrgs    = 2                   // seen by at least this many reporting orgs
	readyAlignedPct = 98.0                // aligned ≥ this % over the window
	dropPoints      = 10.0                // 7-day aligned rate this far below 30-day rate
	dropMinMsgs     = 50                  // with at least this much traffic in the 7-day window
	staleAfter      = 7 * 24 * time.Hour  // no reports for this long → finding
	pruneAfter      = 396 * 24 * time.Hour
)

// SourceStat is one sending source's aggregate over the analysis window.
type SourceStat struct {
	IP        string    `json:"ip"`
	Msgs      int       `json:"msgs"`
	Aligned   int       `json:"aligned"`
	FailBoth  int       `json:"fail_both"`
	FirstEver time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Overview is everything Collect needs about one domain, computed by the store
// in one pass so the collector stays free of SQL.
type Overview struct {
	HasData   bool
	Policy    string // latest published policy seen in reports
	Pct       int
	FirstSeen time.Time // earliest report window start ever
	LastEnd   time.Time // latest report window end ever
	Orgs30    int       // distinct reporting orgs in the long window
	Msgs30    int
	Aligned30 int
	Msgs7     int
	Aligned7  int
	Sources   []SourceStat // long-window sources, FirstEver from all history
}

// Store persists parsed reports and answers aggregate queries.
type Store interface {
	// PutReport stores one report; false means it was a duplicate (same
	// org+report_id+domain) and nothing changed.
	PutReport(rep dmarcrep.Report) (bool, error)
	Overview(domain string, now time.Time) (Overview, error)
	Prune(olderThan time.Time) error
}

// Collector implements core.Collector over a report Store.
type Collector struct {
	store Store
	now   func() time.Time // injectable for tests
}

// New builds the collector.
func New(s Store) *Collector { return &Collector{store: s, now: time.Now} }

// Describe returns module metadata. Report generators send daily; a 6-hour
// affirmation poll keeps "reports stopped" timely without wasted work.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "DmarcWatch",
		Version:         "0.1.0",
		TargetKind:      "maildomain",
		DefaultInterval: 6 * time.Hour,
		ResolveAfter:    1,
	}
}

// ValidateTarget normalises an email domain.
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, ".")
	if i := strings.IndexByte(d, '@'); i >= 0 {
		d = d[i+1:] // let people paste an email address; the domain is what we watch
	}
	if d == "" || strings.ContainsAny(d, " /\\?#") || !strings.Contains(d, ".") {
		return core.Target{}, &core.IngestError{Field: "target", Reason: "enter a bare email domain, e.g. example.com"}
	}
	return core.Target{Raw: raw, Canonical: d}, nil
}

// Collect computes findings for one domain from stored reports.
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	now := c.now()
	_ = c.store.Prune(now.Add(-pruneAfter))

	ov, err := c.store.Overview(t.Canonical, now)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d := t.Canonical

	if !ov.HasData {
		return []core.Finding{{
			Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.no-data", ""),
			Target:      d,
			Check:       "dmarc.no-data",
			Title:       fmt.Sprintf("No DMARC reports ingested yet for %s", d),
			Severity:    core.SeverityInfo,
			Remediation: "Point your DMARC record's rua= address at a mailbox you collect, then upload the report files here (.xml, .xml.gz, or .zip) — or upload an export from your current mailbox to backfill.",
			Evidence:    map[string]any{"domain": d},
		}}, nil
	}

	var out []core.Finding

	// 1. Spoofing: a source failing BOTH aligned mechanisms, at volume.
	for _, s := range ov.Sources {
		if s.FailBoth < spoofMinMsgs || s.Msgs == 0 {
			continue
		}
		failPct := 100 * float64(s.FailBoth) / float64(s.Msgs)
		if failPct < spoofMinFailPct {
			continue
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.spoofing", s.IP),
			Target:      d,
			Check:       "dmarc.spoofing",
			Title:       fmt.Sprintf("Suspected spoofing of %s: %s sent %d message(s) failing both SPF and DKIM", d, s.IP, s.FailBoth),
			Severity:    core.SeverityHigh,
			Remediation: "Confirm this source is not a legitimate sender or a forwarder you use. If it is unknown, your domain is being spoofed — tightening the DMARC policy toward p=reject makes receivers refuse this mail.",
			Evidence: map[string]any{
				"source_ip": s.IP, "messages": s.Msgs, "fail_both": s.FailBoth,
				"fail_pct": int(failPct), "window_days": 30,
			},
		})
	}

	// 2. New sending source (aligned, so likely legitimate — but is it yours?).
	if now.Sub(ov.FirstSeen) >= minHistory {
		cutoff := now.Add(-windowRecent)
		for _, s := range ov.Sources {
			if s.FirstEver.Before(cutoff) || s.Msgs < newSourceMin || s.Aligned == 0 {
				continue
			}
			out = append(out, core.Finding{
				Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.new-source", s.IP),
				Target:      d,
				Check:       "dmarc.new-source",
				Title:       fmt.Sprintf("New sending source for %s: %s (first seen %s)", d, s.IP, s.FirstEver.Format("2006-01-02")),
				Severity:    core.SeverityMedium,
				Remediation: "Confirm this is an expected sender — a newly onboarded SaaS, marketing platform, or forwarder. If nobody recognises it, investigate before it affects your domain's reputation.",
				Evidence:    map[string]any{"source_ip": s.IP, "messages": s.Msgs, "aligned": s.Aligned},
			})
		}
	}

	// 3. Policy progress: the whole point of collecting reports.
	alignedPct30 := pct(ov.Aligned30, ov.Msgs30)
	ready := ov.Msgs30 >= readyMinMsgs && ov.Orgs30 >= readyMinOrgs && alignedPct30 >= readyAlignedPct
	switch ov.Policy {
	case "none", "":
		rem := fmt.Sprintf("Keep collecting reports; once the aligned rate holds at or above %.0f%% you can move to p=quarantine, then p=reject.", readyAlignedPct)
		if ready {
			rem = fmt.Sprintf("Alignment is %.1f%% over the last 30 days across %d reporting org(s) — you are ready to move to p=quarantine (and to p=reject once quarantine runs clean).", alignedPct30, ov.Orgs30)
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.policy", ""),
			Target:      d,
			Check:       "dmarc.policy",
			Title:       fmt.Sprintf("%s publishes p=none — spoofed mail is observed but not stopped", d),
			Severity:    core.SeverityLow,
			Remediation: rem,
			Evidence:    map[string]any{"policy": "none", "aligned_pct_30d": round1(alignedPct30), "messages_30d": ov.Msgs30, "reporting_orgs_30d": ov.Orgs30, "ready_to_tighten": ready},
		})
	case "quarantine":
		if ready {
			out = append(out, core.Finding{
				Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.policy", ""),
				Target:      d,
				Check:       "dmarc.policy",
				Title:       fmt.Sprintf("%s is ready to move from p=quarantine to p=reject", d),
				Severity:    core.SeverityInfo,
				Remediation: fmt.Sprintf("Alignment is %.1f%% over the last 30 days across %d reporting org(s) with quarantine in force — publishing p=reject completes the rollout.", alignedPct30, ov.Orgs30),
				Evidence:    map[string]any{"policy": "quarantine", "aligned_pct_30d": round1(alignedPct30), "messages_30d": ov.Msgs30, "reporting_orgs_30d": ov.Orgs30},
			})
		}
	}

	// 4. Alignment drop: this week materially worse than the month.
	if ov.Msgs7 >= dropMinMsgs && ov.Msgs30 > ov.Msgs7 {
		p7, p30 := pct(ov.Aligned7, ov.Msgs7), alignedPct30
		if p30-p7 >= dropPoints {
			out = append(out, core.Finding{
				Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.alignment-drop", ""),
				Target:      d,
				Check:       "dmarc.alignment-drop",
				Title:       fmt.Sprintf("DMARC alignment for %s dropped to %.1f%% this week (30-day average %.1f%%)", d, p7, p30),
				Severity:    core.SeverityMedium,
				Remediation: "Something changed: a new unaligned sender, a broken DKIM key rotation, or an SPF record edit. Check the sources table for the sources driving the failures.",
				Evidence:    map[string]any{"aligned_pct_7d": round1(p7), "aligned_pct_30d": round1(p30), "messages_7d": ov.Msgs7},
			})
		}
	}

	// 5. Reports stopped arriving — silence is a failure mode, not a success.
	if now.Sub(ov.LastEnd) >= staleAfter {
		days := int(now.Sub(ov.LastEnd).Hours() / 24)
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, d, "dmarc.no-reports", ""),
			Target:      d,
			Check:       "dmarc.no-reports",
			Title:       fmt.Sprintf("No DMARC reports received for %s in %d days", d, days),
			Severity:    core.SeverityMedium,
			Remediation: "Check that the domain's DMARC record still lists your rua= address, that the collecting mailbox works, and that report files are still being uploaded here.",
			Evidence:    map[string]any{"last_report_end": ov.LastEnd.Format(time.RFC3339), "days_silent": days},
		})
	}

	return out, nil
}

// Diff defers to the core's fingerprint-based diff.
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
