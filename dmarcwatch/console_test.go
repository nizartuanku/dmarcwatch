package dmarcwatch

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func newConsoleServer(t *testing.T, domains []string) (*httptest.Server, *MemStore, *[]string) {
	t.Helper()
	st := NewMemStore()
	var rescanned []string
	c := &Console{
		Store:    st,
		Domains:  func() []string { return domains },
		OnIngest: func(ds []string) { rescanned = append(rescanned, ds...) },
	}
	mux := http.NewServeMux()
	c.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st, &rescanned
}

func uploadXML(t *testing.T, url string, files map[string][]byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for name, data := range files {
		fw, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(data)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", url+"/api/dmarcwatch/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func liveXML(domain, org, id string) []byte {
	end := time.Now().UTC().Add(-24 * time.Hour).Unix()
	return []byte(`<?xml version="1.0"?><feedback>
<report_metadata><org_name>` + org + `</org_name><report_id>` + id + `</report_id>
<date_range><begin>` + itoa(end-86400) + `</begin><end>` + itoa(end) + `</end></date_range></report_metadata>
<policy_published><domain>` + domain + `</domain><p>none</p></policy_published>
<record><row><source_ip>203.0.113.10</source_ip><count>7</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>` + domain + `</header_from></identifiers></record></feedback>`)
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func TestUploadFlow(t *testing.T) {
	srv, _, rescanned := newConsoleServer(t, []string{"example.com"})

	resp := uploadXML(t, srv.URL, map[string][]byte{
		"good.xml":    liveXML("example.com", "google.com", "u1"),
		"foreign.xml": liveXML("not-mine.org", "google.com", "u2"),
		"broken.xml":  []byte("this is not xml at all"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var res uploadResult
	json.NewDecoder(resp.Body).Decode(&res)
	if res.Ingested != 1 {
		t.Errorf("ingested = %d, want 1", res.Ingested)
	}
	if res.SkippedUnknown["not-mine.org"] != 1 {
		t.Errorf("unknown domain not reported: %+v", res.SkippedUnknown)
	}
	if len(res.FailedFiles) != 1 {
		t.Errorf("broken file not reported: %+v", res.FailedFiles)
	}
	if len(*rescanned) == 0 {
		t.Error("ingest did not trigger a rescan")
	}

	// Same file again → duplicate, no new rescan domains needed but harmless.
	resp2 := uploadXML(t, srv.URL, map[string][]byte{"good.xml": liveXML("example.com", "google.com", "u1")})
	defer resp2.Body.Close()
	var res2 uploadResult
	json.NewDecoder(resp2.Body).Decode(&res2)
	if res2.Duplicates != 1 || res2.Ingested != 0 {
		t.Errorf("dup handling wrong: %+v", res2)
	}
}

func TestUploadRejectsEmpty(t *testing.T) {
	srv, _, _ := newConsoleServer(t, []string{"example.com"})
	resp := uploadXML(t, srv.URL, map[string][]byte{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestSummaryAndSources(t *testing.T) {
	srv, st, _ := newConsoleServer(t, []string{"example.com", "empty.example"})
	up := uploadXML(t, srv.URL, map[string][]byte{"a.xml": liveXML("example.com", "google.com", "s1")})
	up.Body.Close()
	_ = st

	resp, err := http.Get(srv.URL + "/api/dmarcwatch/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sum struct {
		Domains []domainSummary `json:"domains"`
	}
	json.NewDecoder(resp.Body).Decode(&sum)
	if len(sum.Domains) != 2 {
		t.Fatalf("want 2 domains, got %d", len(sum.Domains))
	}
	byName := map[string]domainSummary{}
	for _, d := range sum.Domains {
		byName[d.Domain] = d
	}
	if !byName["example.com"].HasData || byName["example.com"].Msgs30 != 7 {
		t.Errorf("example.com summary wrong: %+v", byName["example.com"])
	}
	if byName["empty.example"].HasData {
		t.Errorf("empty domain should have no data")
	}

	resp2, err := http.Get(srv.URL + "/api/dmarcwatch/sources?domain=example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var src struct {
		Sources []SourceStat `json:"sources"`
	}
	json.NewDecoder(resp2.Body).Decode(&src)
	if len(src.Sources) != 1 || src.Sources[0].IP != "203.0.113.10" || src.Sources[0].Msgs != 7 {
		t.Errorf("sources wrong: %+v", src.Sources)
	}
}
