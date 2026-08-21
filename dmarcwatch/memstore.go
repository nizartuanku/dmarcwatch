package dmarcwatch

import (
	"sync"
	"time"

	"github.com/nizartuanku/dmarcwatch/dmarcrep"
)

// MemStore is the in-memory Store used by tests. It mirrors SQLiteStore's
// semantics exactly (dedup key, window maths) so collector tests exercise the
// same contract production runs on.
type MemStore struct {
	mu      sync.Mutex
	reports map[string]dmarcrep.Report // key: rep.Key()
}

// NewMemStore builds an empty store.
func NewMemStore() *MemStore { return &MemStore{reports: map[string]dmarcrep.Report{}} }

// PutReport stores one report; false = duplicate.
func (m *MemStore) PutReport(rep dmarcrep.Report) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.reports[rep.Key()]; dup {
		return false, nil
	}
	m.reports[rep.Key()] = rep
	return true, nil
}

// Overview mirrors the SQL implementation.
func (m *MemStore) Overview(domain string, now time.Time) (Overview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ov Overview
	long := now.Add(-windowLong)
	recent := now.Add(-windowRecent)

	type agg struct{ SourceStat }
	sources := map[string]*agg{}
	firstEver := map[string]time.Time{}
	orgs := map[string]bool{}

	for _, rep := range m.reports {
		if rep.Domain != domain {
			continue
		}
		if !ov.HasData || rep.Begin.Before(ov.FirstSeen) {
			ov.FirstSeen = rep.Begin
		}
		if rep.End.After(ov.LastEnd) {
			ov.LastEnd = rep.End
			ov.Policy, ov.Pct = rep.Policy, rep.Pct
		}
		ov.HasData = true

		for _, r := range rep.Records {
			if fe, ok := firstEver[r.SourceIP]; !ok || rep.Begin.Before(fe) {
				firstEver[r.SourceIP] = rep.Begin
			}
		}
		if rep.End.Before(long) {
			continue
		}
		orgs[rep.Org] = true
		for _, r := range rep.Records {
			ov.Msgs30 += r.Count
			if r.Aligned() {
				ov.Aligned30 += r.Count
			}
			if !rep.End.Before(recent) {
				ov.Msgs7 += r.Count
				if r.Aligned() {
					ov.Aligned7 += r.Count
				}
			}
			a, ok := sources[r.SourceIP]
			if !ok {
				a = &agg{SourceStat{IP: r.SourceIP}}
				sources[r.SourceIP] = a
			}
			a.Msgs += r.Count
			if r.Aligned() {
				a.Aligned += r.Count
			} else {
				a.FailBoth += r.Count
			}
			if rep.End.After(a.LastSeen) {
				a.LastSeen = rep.End
			}
		}
	}
	ov.Orgs30 = len(orgs)
	for ip, a := range sources {
		a.FirstEver = firstEver[ip]
		ov.Sources = append(ov.Sources, a.SourceStat)
	}
	return ov, nil
}

// Prune drops reports older than the horizon.
func (m *MemStore) Prune(olderThan time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rep := range m.reports {
		if rep.End.Before(olderThan) {
			delete(m.reports, k)
		}
	}
	return nil
}
