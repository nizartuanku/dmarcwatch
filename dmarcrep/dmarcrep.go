// Package dmarcrep parses DMARC aggregate (RUA) reports. It accepts the three
// shapes report generators actually send — raw XML, gzip-compressed XML
// (.xml.gz), and ZIP archives containing one or more XML files — and normalises
// them into a vendor-neutral Report model.
//
// The parser is deliberately forgiving about optional fields (real-world
// reports from smaller senders omit plenty) but strict about the parts that
// carry meaning: a report without metadata, a policy domain, or any records is
// rejected rather than half-ingested.
package dmarcrep

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// MaxDecompressedBytes caps how much XML a single compressed member may expand
// to. DMARC reports are small (KBs); anything past this is either corrupt or
// hostile (zip bomb), and we refuse it rather than exhaust memory.
const MaxDecompressedBytes = 32 << 20 // 32 MiB

// Report is one parsed aggregate report.
type Report struct {
	Org        string    // report_metadata > org_name
	Email      string    // report_metadata > email
	ReportID   string    // report_metadata > report_id
	Begin, End time.Time // report_metadata > date_range
	Domain     string    // policy_published > domain (lower-cased)
	Policy     string    // policy_published > p ("none" | "quarantine" | "reject")
	SubPolicy  string    // policy_published > sp
	Pct        int       // policy_published > pct (100 when absent)
	Records    []Record
}

// Record is one <record> row: a source IP with its counts and outcomes.
type Record struct {
	SourceIP    string // as reported
	Count       int
	Disposition string // policy_evaluated > disposition
	EvalDKIM    string // policy_evaluated > dkim  ("pass"/"fail") — ALIGNED result
	EvalSPF     string // policy_evaluated > spf   ("pass"/"fail") — ALIGNED result
	HeaderFrom  string // identifiers > header_from
	AuthDKIM    string // first auth_results > dkim domain (raw signal, unaligned)
	AuthSPF     string // first auth_results > spf domain
}

// Aligned reports whether the message passed DMARC: at least one of the
// policy-evaluated (i.e. aligned) SPF or DKIM results is a pass.
func (r Record) Aligned() bool {
	return strings.EqualFold(r.EvalDKIM, "pass") || strings.EqualFold(r.EvalSPF, "pass")
}

// FailsBoth reports whether the message failed BOTH aligned mechanisms — the
// signature of spoofing (or a badly broken legitimate sender).
func (r Record) FailsBoth() bool { return !r.Aligned() }

// Key identifies a report for dedup: generators resend the same report, and
// the same report often arrives once by mail and once by upload.
func (r Report) Key() string { return r.Org + "|" + r.ReportID + "|" + r.Domain }

// ---- wire format (subset of RFC 7489 appendix C) ---------------------------

type xmlFeedback struct {
	Metadata xmlMetadata  `xml:"report_metadata"`
	Policy   xmlPolicyPub `xml:"policy_published"`
	Records  []xmlRecord  `xml:"record"`
}

type xmlMetadata struct {
	OrgName  string       `xml:"org_name"`
	Email    string       `xml:"email"`
	ReportID string       `xml:"report_id"`
	Range    xmlDateRange `xml:"date_range"`
}

type xmlDateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type xmlPolicyPub struct {
	Domain string `xml:"domain"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    *int   `xml:"pct"`
}

type xmlRecord struct {
	Row struct {
		SourceIP string `xml:"source_ip"`
		Count    int    `xml:"count"`
		Policy   struct {
			Disposition string `xml:"disposition"`
			DKIM        string `xml:"dkim"`
			SPF         string `xml:"spf"`
		} `xml:"policy_evaluated"`
	} `xml:"row"`
	Identifiers struct {
		HeaderFrom string `xml:"header_from"`
	} `xml:"identifiers"`
	AuthResults struct {
		DKIM []struct {
			Domain string `xml:"domain"`
			Result string `xml:"result"`
		} `xml:"dkim"`
		SPF []struct {
			Domain string `xml:"domain"`
			Result string `xml:"result"`
		} `xml:"spf"`
	} `xml:"auth_results"`
}

// ---- entry points ----------------------------------------------------------

// ErrNotAReport marks payloads that are readable but are not DMARC aggregate
// reports (wrong root element, no records at all).
var ErrNotAReport = errors.New("not a DMARC aggregate report")

// ParseFile sniffs the payload format by content (never trusting the filename
// alone) and returns every report found. A ZIP may contain several XML members;
// each becomes one Report. Filename is used only for error messages.
func ParseFile(filename string, data []byte) ([]Report, error) {
	switch {
	case len(data) >= 4 && data[0] == 'P' && data[1] == 'K':
		return parseZip(filename, data)
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		xmlBytes, err := gunzip(data)
		if err != nil {
			return nil, fmt.Errorf("%s: gzip: %w", filename, err)
		}
		rep, err := ParseXML(xmlBytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		return []Report{rep}, nil
	default:
		rep, err := ParseXML(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		return []Report{rep}, nil
	}
}

// ParseXML parses one raw XML aggregate report.
func ParseXML(data []byte) (Report, error) {
	var fb xmlFeedback
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false // real-world reports contain stray entities; be tolerant
	if err := dec.Decode(&fb); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrNotAReport, err)
	}
	if fb.Metadata.OrgName == "" && fb.Metadata.ReportID == "" {
		return Report{}, fmt.Errorf("%w: missing report_metadata", ErrNotAReport)
	}
	domain := strings.ToLower(strings.TrimSpace(fb.Policy.Domain))
	if domain == "" {
		return Report{}, fmt.Errorf("%w: missing policy_published>domain", ErrNotAReport)
	}
	if len(fb.Records) == 0 {
		return Report{}, fmt.Errorf("%w: no records", ErrNotAReport)
	}

	rep := Report{
		Org:       strings.TrimSpace(fb.Metadata.OrgName),
		Email:     strings.TrimSpace(fb.Metadata.Email),
		ReportID:  strings.TrimSpace(fb.Metadata.ReportID),
		Begin:     time.Unix(fb.Metadata.Range.Begin, 0).UTC(),
		End:       time.Unix(fb.Metadata.Range.End, 0).UTC(),
		Domain:    domain,
		Policy:    strings.ToLower(strings.TrimSpace(fb.Policy.P)),
		SubPolicy: strings.ToLower(strings.TrimSpace(fb.Policy.SP)),
		Pct:       100,
	}
	if fb.Policy.Pct != nil {
		rep.Pct = *fb.Policy.Pct
	}
	for _, xr := range fb.Records {
		rec := Record{
			SourceIP:    normalizeIP(xr.Row.SourceIP),
			Count:       xr.Row.Count,
			Disposition: strings.ToLower(strings.TrimSpace(xr.Row.Policy.Disposition)),
			EvalDKIM:    strings.ToLower(strings.TrimSpace(xr.Row.Policy.DKIM)),
			EvalSPF:     strings.ToLower(strings.TrimSpace(xr.Row.Policy.SPF)),
			HeaderFrom:  strings.ToLower(strings.TrimSpace(xr.Identifiers.HeaderFrom)),
		}
		if rec.Count <= 0 {
			rec.Count = 1 // some generators omit count for single messages
		}
		if len(xr.AuthResults.DKIM) > 0 {
			rec.AuthDKIM = strings.ToLower(xr.AuthResults.DKIM[0].Domain)
		}
		if len(xr.AuthResults.SPF) > 0 {
			rec.AuthSPF = strings.ToLower(xr.AuthResults.SPF[0].Domain)
		}
		if rec.SourceIP == "" {
			continue // a row with no source is meaningless; skip it, keep the rest
		}
		rep.Records = append(rep.Records, rec)
	}
	if len(rep.Records) == 0 {
		return Report{}, fmt.Errorf("%w: all records lacked a source_ip", ErrNotAReport)
	}
	return rep, nil
}

func parseZip(filename string, data []byte) ([]Report, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%s: zip: %w", filename, err)
	}
	var out []Report
	var firstErr error
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".xml") && !strings.HasSuffix(name, ".xml.gz") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		member, err := io.ReadAll(io.LimitReader(rc, MaxDecompressedBytes+1))
		rc.Close()
		if err != nil || int64(len(member)) > MaxDecompressedBytes {
			continue
		}
		reps, err := ParseFile(f.Name, member)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, reps...)
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("%s: %w: zip contains no report XML", filename, ErrNotAReport)
	}
	return out, nil
}

func gunzip(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	out, err := io.ReadAll(io.LimitReader(gr, MaxDecompressedBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > MaxDecompressedBytes {
		return nil, errors.New("decompressed payload exceeds size cap")
	}
	return out, nil
}

// normalizeIP canonicalises the reported source IP (some generators pad or
// upper-case IPv6). Unparseable values are kept verbatim — the report is still
// evidence even when the generator wrote a strange address.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
