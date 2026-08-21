package dmarcwatch

import (
	"database/sql"
	"time"

	"github.com/nizartuanku/dmarcwatch/dmarcrep"
)

// SQLiteStore persists reports in two tables: one row per report (dedup key),
// one row per record. All aggregate queries run in SQL so the Go side stays a
// straight translation of the Overview contract.
type SQLiteStore struct{ db *sql.DB }

// NewSQLiteStore creates the schema when absent.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	schema := `
CREATE TABLE IF NOT EXISTS dmarc_reports (
	domain     TEXT NOT NULL,
	org        TEXT NOT NULL,
	report_id  TEXT NOT NULL,
	begin_at   INTEGER NOT NULL,
	end_at     INTEGER NOT NULL,
	policy     TEXT NOT NULL,
	pct        INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	PRIMARY KEY (domain, org, report_id)
);
CREATE TABLE IF NOT EXISTS dmarc_rows (
	domain     TEXT NOT NULL,
	org        TEXT NOT NULL,
	report_id  TEXT NOT NULL,
	source_ip  TEXT NOT NULL,
	cnt        INTEGER NOT NULL,
	disposition TEXT NOT NULL,
	eval_dkim  TEXT NOT NULL,
	eval_spf   TEXT NOT NULL,
	header_from TEXT NOT NULL,
	end_at     INTEGER NOT NULL,
	begin_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dmarc_rows_domain_end ON dmarc_rows(domain, end_at);
CREATE INDEX IF NOT EXISTS idx_dmarc_reports_domain_end ON dmarc_reports(domain, end_at);
`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// PutReport stores one parsed report; false = duplicate.
func (s *SQLiteStore) PutReport(rep dmarcrep.Report) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT OR IGNORE INTO dmarc_reports
		(domain, org, report_id, begin_at, end_at, policy, pct, received_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		rep.Domain, rep.Org, rep.ReportID, rep.Begin.Unix(), rep.End.Unix(),
		rep.Policy, rep.Pct, time.Now().Unix())
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil // duplicate
	}
	for _, r := range rep.Records {
		if _, err := tx.Exec(`INSERT INTO dmarc_rows
			(domain, org, report_id, source_ip, cnt, disposition, eval_dkim, eval_spf, header_from, end_at, begin_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			rep.Domain, rep.Org, rep.ReportID, r.SourceIP, r.Count, r.Disposition,
			r.EvalDKIM, r.EvalSPF, r.HeaderFrom, rep.End.Unix(), rep.Begin.Unix()); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// Overview computes the collector's per-domain aggregate view.
func (s *SQLiteStore) Overview(domain string, now time.Time) (Overview, error) {
	var ov Overview
	long := now.Add(-windowLong).Unix()
	recent := now.Add(-windowRecent).Unix()

	// Report-level facts: history bounds, latest policy, org count.
	var first, last sql.NullInt64
	err := s.db.QueryRow(`SELECT MIN(begin_at), MAX(end_at) FROM dmarc_reports WHERE domain=?`, domain).Scan(&first, &last)
	if err != nil {
		return ov, err
	}
	if !last.Valid {
		return ov, nil // no data
	}
	ov.HasData = true
	ov.FirstSeen = time.Unix(first.Int64, 0).UTC()
	ov.LastEnd = time.Unix(last.Int64, 0).UTC()

	if err := s.db.QueryRow(`SELECT policy, pct FROM dmarc_reports WHERE domain=? ORDER BY end_at DESC LIMIT 1`, domain).
		Scan(&ov.Policy, &ov.Pct); err != nil {
		return ov, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT org) FROM dmarc_reports WHERE domain=? AND end_at>=?`, domain, long).
		Scan(&ov.Orgs30); err != nil {
		return ov, err
	}

	// Message totals for the two windows.
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(cnt),0),
		COALESCE(SUM(CASE WHEN eval_dkim='pass' OR eval_spf='pass' THEN cnt ELSE 0 END),0)
		FROM dmarc_rows WHERE domain=? AND end_at>=?`, domain, long).
		Scan(&ov.Msgs30, &ov.Aligned30); err != nil {
		return ov, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(cnt),0),
		COALESCE(SUM(CASE WHEN eval_dkim='pass' OR eval_spf='pass' THEN cnt ELSE 0 END),0)
		FROM dmarc_rows WHERE domain=? AND end_at>=?`, domain, recent).
		Scan(&ov.Msgs7, &ov.Aligned7); err != nil {
		return ov, err
	}

	// Per-source stats over the long window, with all-history first_seen.
	rows, err := s.db.Query(`SELECT w.source_ip, w.msgs, w.aligned, w.fail_both, h.first_ever, w.last_seen
		FROM (
			SELECT source_ip,
				SUM(cnt) AS msgs,
				SUM(CASE WHEN eval_dkim='pass' OR eval_spf='pass' THEN cnt ELSE 0 END) AS aligned,
				SUM(CASE WHEN eval_dkim<>'pass' AND eval_spf<>'pass' THEN cnt ELSE 0 END) AS fail_both,
				MAX(end_at) AS last_seen
			FROM dmarc_rows WHERE domain=? AND end_at>=? GROUP BY source_ip
		) w
		JOIN (
			SELECT source_ip, MIN(begin_at) AS first_ever FROM dmarc_rows WHERE domain=? GROUP BY source_ip
		) h ON h.source_ip = w.source_ip
		ORDER BY w.msgs DESC`, domain, long, domain)
	if err != nil {
		return ov, err
	}
	defer rows.Close()
	for rows.Next() {
		var st SourceStat
		var firstEver, lastSeen int64
		if err := rows.Scan(&st.IP, &st.Msgs, &st.Aligned, &st.FailBoth, &firstEver, &lastSeen); err != nil {
			return ov, err
		}
		st.FirstEver = time.Unix(firstEver, 0).UTC()
		st.LastSeen = time.Unix(lastSeen, 0).UTC()
		ov.Sources = append(ov.Sources, st)
	}
	return ov, rows.Err()
}

// Prune drops rows older than the retention horizon.
func (s *SQLiteStore) Prune(olderThan time.Time) error {
	cut := olderThan.Unix()
	if _, err := s.db.Exec(`DELETE FROM dmarc_rows WHERE end_at<?`, cut); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM dmarc_reports WHERE end_at<?`, cut)
	return err
}
