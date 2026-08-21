package dmarcrep

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"
	"time"
)

// sampleXML builds a realistic aggregate report in the shape Google sends.
func sampleXML(domain, org, reportID string, begin, end int64) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>%s</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>%s</report_id>
    <date_range><begin>%d</begin><end>%d</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>%s</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.10</source_ip>
      <count>42</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>%s</header_from></identifiers>
    <auth_results>
      <dkim><domain>%s</domain><result>pass</result></dkim>
      <spf><domain>%s</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>13</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>%s</header_from></identifiers>
    <auth_results>
      <spf><domain>spoofer.example</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>`, org, reportID, begin, end, domain, domain, domain, domain, domain))
}

func TestParseXML(t *testing.T) {
	begin := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC).Unix()
	reps, err := ParseFile("google.xml", sampleXML("Example.COM", "google.com", "r1", begin, end))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reps) != 1 {
		t.Fatalf("want 1 report, got %d", len(reps))
	}
	r := reps[0]
	if r.Domain != "example.com" {
		t.Errorf("domain not lower-cased: %q", r.Domain)
	}
	if r.Org != "google.com" || r.ReportID != "r1" || r.Policy != "none" || r.Pct != 100 {
		t.Errorf("metadata wrong: %+v", r)
	}
	if len(r.Records) != 2 {
		t.Fatalf("want 2 records, got %d", len(r.Records))
	}
	if !r.Records[0].Aligned() || r.Records[0].Count != 42 {
		t.Errorf("record 0 wrong: %+v", r.Records[0])
	}
	if !r.Records[1].FailsBoth() {
		t.Errorf("record 1 should fail both: %+v", r.Records[1])
	}
	if r.Key() != "google.com|r1|example.com" {
		t.Errorf("key: %q", r.Key())
	}
}

func TestParseGzipAndZip(t *testing.T) {
	xmlBytes := sampleXML("example.com", "yahoo", "r2", 100, 200)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(xmlBytes)
	zw.Close()
	reps, err := ParseFile("report.xml.gz", gz.Bytes())
	if err != nil || len(reps) != 1 {
		t.Fatalf("gzip: %v (%d reports)", err, len(reps))
	}

	var zbuf bytes.Buffer
	zipw := zip.NewWriter(&zbuf)
	f1, _ := zipw.Create("a.xml")
	f1.Write(sampleXML("example.com", "outlook.com", "r3", 100, 200))
	f2, _ := zipw.Create("b.xml")
	f2.Write(sampleXML("example.com", "google.com", "r4", 100, 200))
	f3, _ := zipw.Create("notes.txt") // must be ignored
	f3.Write([]byte("hi"))
	zipw.Close()
	reps, err = ParseFile("bundle.zip", zbuf.Bytes())
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	if len(reps) != 2 {
		t.Fatalf("zip: want 2 reports, got %d", len(reps))
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for name, payload := range map[string][]byte{
		"not xml":      []byte("hello world"),
		"wrong xml":    []byte("<html><body>nope</body></html>"),
		"no records":   []byte(`<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published></feedback>`),
		"no domain":    []byte(`<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata><policy_published><p>none</p></policy_published></feedback>`),
	} {
		if _, err := ParseFile(name, payload); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	if got := normalizeIP("2001:0DB8:0000:0000:0000:0000:0000:0001"); got != "2001:db8::1" {
		t.Errorf("ipv6 not canonicalised: %q", got)
	}
	if got := normalizeIP("not-an-ip"); got != "not-an-ip" {
		t.Errorf("unparseable IP should be kept verbatim: %q", got)
	}
}
