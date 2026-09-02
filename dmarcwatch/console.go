package dmarcwatch

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nizartuanku/dmarcwatch/dmarcrep"
)

// Upload guardrails: DMARC report files are kilobytes; these caps keep a
// mistaken (or hostile) upload from hurting the process.
const (
	maxUploadFiles    = 50
	maxUploadFileSize = 16 << 20 // per file, pre-decompression
	maxUploadTotal    = 64 << 20
)

// Console serves DmarcWatch's product endpoints: report upload, a per-domain
// summary for the dashboard panel, and the per-source table. Domains
// themselves are core targets — added and removed through the core target API.
type Console struct {
	Store    Store
	Domains  func() []string        // registered domains (canonical), from the scheduler
	OnIngest func(domains []string) // trigger an immediate rescan after ingest
}

// Register mounts the console routes.
func (c *Console) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/dmarcwatch/upload", c.handleUpload)
	mux.HandleFunc("GET /api/dmarcwatch/summary", c.handleSummary)
	mux.HandleFunc("GET /api/dmarcwatch/sources", c.handleSources)
}

type uploadResult struct {
	Ingested       int            `json:"ingested"`
	Duplicates     int            `json:"duplicates"`
	SkippedUnknown map[string]int `json:"skipped_unknown,omitempty"` // domain → reports skipped
	FailedFiles    []string       `json:"failed_files,omitempty"`
	Domains        []string       `json:"domains,omitempty"` // domains that received data
}

func (c *Console) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadTotal)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		httpErr(w, http.StatusBadRequest, "upload too large or malformed: "+err.Error())
		return
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		httpErr(w, http.StatusBadRequest, "no files — send multipart field \"files\"")
		return
	}
	if len(files) > maxUploadFiles {
		httpErr(w, http.StatusBadRequest, "too many files in one upload (max 50)")
		return
	}

	registered := map[string]bool{}
	for _, d := range c.Domains() {
		registered[d] = true
	}

	res := uploadResult{SkippedUnknown: map[string]int{}}
	touched := map[string]bool{}
	for _, fh := range files {
		if fh.Size > maxUploadFileSize {
			res.FailedFiles = append(res.FailedFiles, fh.Filename+" (too large)")
			continue
		}
		f, err := fh.Open()
		if err != nil {
			res.FailedFiles = append(res.FailedFiles, fh.Filename)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxUploadFileSize+1))
		f.Close()
		if err != nil || int64(len(data)) > maxUploadFileSize {
			res.FailedFiles = append(res.FailedFiles, fh.Filename)
			continue
		}
		reps, err := dmarcrep.ParseFile(fh.Filename, data)
		if err != nil {
			res.FailedFiles = append(res.FailedFiles, fh.Filename)
			continue
		}
		for _, rep := range reps {
			if !registered[rep.Domain] {
				res.SkippedUnknown[rep.Domain]++
				continue
			}
			stored, err := c.Store.PutReport(rep)
			if err != nil {
				httpErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			if stored {
				res.Ingested++
				touched[rep.Domain] = true
			} else {
				res.Duplicates++
			}
		}
	}
	if len(res.SkippedUnknown) == 0 {
		res.SkippedUnknown = nil
	}
	for d := range touched {
		res.Domains = append(res.Domains, d)
	}
	sort.Strings(res.Domains)
	if len(res.Domains) > 0 && c.OnIngest != nil {
		c.OnIngest(res.Domains)
	}
	writeJSON(w, http.StatusOK, res)
}

type domainSummary struct {
	Domain     string  `json:"domain"`
	Policy     string  `json:"policy"`
	Msgs30     int     `json:"msgs_30d"`
	AlignedPct float64 `json:"aligned_pct_30d"`
	Sources    int     `json:"sources_30d"`
	Orgs       int     `json:"orgs_30d"`
	LastReport string  `json:"last_report,omitempty"`
	HasData    bool    `json:"has_data"`
}

func (c *Console) handleSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	domains := c.Domains()
	sort.Strings(domains)
	out := make([]domainSummary, 0, len(domains))
	for _, d := range domains {
		ov, err := c.Store.Overview(d, now)
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		ds := domainSummary{Domain: d, Policy: ov.Policy, Msgs30: ov.Msgs30,
			AlignedPct: round1(pct(ov.Aligned30, ov.Msgs30)), Sources: len(ov.Sources),
			Orgs: ov.Orgs30, HasData: ov.HasData}
		if ov.HasData {
			ds.LastReport = ov.LastEnd.Format("2006-01-02")
		}
		out = append(out, ds)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

func (c *Console) handleSources(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if d == "" {
		httpErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	ov, err := c.Store.Overview(d, time.Now())
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ov.Sources == nil {
		ov.Sources = []SourceStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": d, "sources": ov.Sources})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
