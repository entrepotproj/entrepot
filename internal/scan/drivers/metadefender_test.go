package drivers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/scan/drivers/mdfake"
)

func mdFile(name, content string) File {
	sum := sha256.Sum256([]byte(content))
	return File{Name: name, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]),
		Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil }}
}

func newMD(srv *mdfake.Server) *MetaDefender {
	return &MetaDefender{URL: srv.URL, Rule: "File process", Concurrency: 4, HashLookup: true, MaxResultAge: 24 * time.Hour,
		PollMin: 2 * time.Millisecond, PollMax: 10 * time.Millisecond, BusyBackoff: 2 * time.Millisecond}
}

func scanFiles(t *testing.T, md *MetaDefender, files ...File) (*Outcome, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return md.Scan(ctx, Target{Kind: KindFiles, Files: files})
}

func mustScan(t *testing.T, md *MetaDefender, files ...File) *Outcome {
	t.Helper()
	o, err := scanFiles(t, md, files...)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestMetaDefenderClean(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.APIKey = "k3y"
	md := newMD(srv)
	md.APIKey = "k3y"
	md.WebURL = "https://md.example/#/public/process/dataId/{dataId}"
	f := mdFile("left pad+1.tgz", "harmless")
	f.Label = "left-pad/-/left pad+1.tgz"
	o := mustScan(t, md, f)
	if o.Status != StatusOK || len(o.Findings) != 0 || o.ScannerVersion != "5.24.2" || o.DBVersion != "2026-01-01T06:00:00.000Z" {
		t.Fatalf("outcome: %+v", o)
	}
	if len(o.Files) != 1 || o.Files[0].Cached || o.Files[0].DataID == "" || o.Files[0].Result != "No Threat Detected" ||
		o.Files[0].Name != f.Label || o.Files[0].SHA256 != f.SHA256 {
		t.Fatalf("files: %+v", o.Files)
	}
	h := srv.UploadHeaders
	if h.Get("Content-Type") != "application/octet-stream" || h.Get("Content-Length") != "8" || h.Get("apikey") != "k3y" ||
		h.Get("rule") != "File%20process" || h.Get("filename") != "left%20pad%2B1.tgz" {
		t.Fatalf("upload headers: %v", h)
	}
	if a := srv.Analyses(); len(a) != 1 || a[0].Name != "left pad+1.tgz" || a[0].Rule != "File process" {
		t.Fatalf("analysis: %+v", a[0])
	}
}

func TestMetaDefenderVerdicts(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	md := newMD(srv)
	md.WebURL = "https://md.example/r/{dataId}"
	cases := []struct {
		marker, id, severity, title string
	}{
		{"X-MDFAKE-MALWARE", "MALWARE:Virus eicar test file", "critical", "Infected: 3/3 engines"},
		{"X-MDFAKE-SUSPICIOUS", "SUSPICIOUS:Heuristic.Packed", "critical", "Suspicious: 1/3 engines"},
		{"X-MDFAKE-PUA", "PUA:PUA.Win.Adware.Generic", "critical", "Potentially Unwanted: 1/3 engines"},
		{"X-MDFAKE-ALLOWED-PUA", "PUA:PUA.Win.Adware.Generic", "high", "Potentially Unwanted: 1/3 engines"},
		{"X-MDFAKE-ENCRYPTED", "BLOCKED:Encrypted Archive", "critical", "Encrypted Archive: 0/3 engines"},
	}
	for _, c := range cases {
		t.Run(c.marker, func(t *testing.T) {
			f := mdFile("x.bin", "data "+c.marker)
			o := mustScan(t, md, f)
			if len(o.Findings) != 1 {
				t.Fatalf("findings: %+v", o.Findings)
			}
			got := o.Findings[0]
			if got.VulnID != c.id || got.Severity != c.severity || got.Title != c.title || got.Package != "x.bin" ||
				got.InstalledVersion != f.SHA256[:12] || got.URL != "https://md.example/r/"+o.Files[0].DataID {
				t.Fatalf("finding: %+v", got)
			}
		})
	}
	if _, err := scanFiles(t, md, mdFile("x.bin", "X-MDFAKE-FAIL")); err == nil || !strings.Contains(err.Error(), "could not analyse x.bin: Failed") {
		t.Fatalf("failed analysis: %v", err)
	}
}

func TestMetaDefenderArchiveLeaves(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	f := mdFile("tool-1.0.tgz", "X-MDFAKE-ARCHIVE")
	f.Label = "tools/tool-1.0.tgz"
	o := mustScan(t, newMD(srv), f)
	if len(o.Findings) != 1 {
		t.Fatalf("findings: %+v", o.Findings)
	}
	got := o.Findings[0]
	if got.VulnID != "MALWARE:Virus eicar test file" || got.Package != "tools/tool-1.0.tgz › bin/payload.exe" ||
		got.Title != "Infected inside the archive" {
		t.Fatalf("leaf finding: %+v", got)
	}
}

func TestMetaDefenderBusy(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.Busy = 2
	mustScan(t, newMD(srv), mdFile("a", "a"))
	if up, _, _ := srv.Counts(); up != 1 || srv.Requests["POST /file"] != 3 {
		t.Fatalf("uploads %d, requests %v", up, srv.Requests)
	}

	srv.AlwaysBusy = true
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := newMD(srv).Scan(ctx, Target{Kind: KindFiles, Files: []File{mdFile("b", "b")}})
	if err == nil || !strings.Contains(err.Error(), "stayed busy") {
		t.Fatalf("always busy: %v", err)
	}
}

func TestMetaDefenderTimeoutCancels(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.Never = true
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := newMD(srv).Scan(ctx, Target{Kind: KindFiles, Files: []File{mdFile("slow", "slow")}})
	if err == nil || !strings.Contains(err.Error(), "did not finish analysing slow (40% done)") {
		t.Fatalf("timeout: %v", err)
	}
	if c := srv.Canceled(); len(c) != 1 {
		t.Fatalf("cancelled: %v", c)
	}

	// Shutting down (cancelled, not timed out) leaves the analysis running.
	srv2 := mdfake.New()
	defer srv2.Close()
	srv2.Never = true
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel2)
	if _, err := newMD(srv2).Scan(ctx2, Target{Kind: KindFiles, Files: []File{mdFile("slow", "slow")}}); err == nil {
		t.Fatal("expected an error")
	}
	if c := srv2.Canceled(); len(c) != 0 {
		t.Fatalf("cancelled on shutdown: %v", c)
	}
}

func TestMetaDefenderHashLookup(t *testing.T) {
	for _, notFound404 := range []bool{false, true} {
		t.Run(fmt.Sprint("404=", notFound404), func(t *testing.T) {
			srv := mdfake.New()
			defer srv.Close()
			srv.HashNotFound404 = notFound404
			md := newMD(srv)
			f := mdFile("a.whl", "wheel")
			if o := mustScan(t, md, f); o.Files[0].Cached {
				t.Fatal("first scan cached")
			}
			o := mustScan(t, md, f)
			if up, lookups, _ := srv.Counts(); up != 1 || lookups != 2 || !o.Files[0].Cached {
				t.Fatalf("second scan: uploads %d lookups %d files %+v", up, lookups, o.Files)
			}

			// Another rule's analysis is not reused.
			other := newMD(srv)
			other.Rule = "Packages"
			mustScan(t, other, f)
			if up, _, _ := srv.Counts(); up != 2 {
				t.Fatalf("other rule: uploads %d", up)
			}

			// Outdated engine definitions, or too old: analysed again.
			srv.Do(func(s *mdfake.Server) {
				s.Mutate = func(a *mdfake.Analysis, res map[string]any) {
					res["process_info"].(map[string]any)["outdated_data"] = []string{"enginedefinitions"}
				}
			})
			mustScan(t, other, f)
			srv.Do(func(s *mdfake.Server) {
				s.Mutate = func(a *mdfake.Analysis, res map[string]any) {
					res["scan_results"].(map[string]any)["start_time"] = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
				}
			})
			o = mustScan(t, other, f)
			if up, _, _ := srv.Counts(); up != 4 {
				t.Fatalf("stale results reused: uploads %d", up)
			}
			if srv.Requests["GET /hash/{hash}"] != 5 {
				t.Fatalf("lookups: %v", srv.Requests)
			}

			// Lookups can be turned off.
			srv.Do(func(s *mdfake.Server) { s.Mutate = nil })
			md.HashLookup = false
			mustScan(t, md, f)
			if up, lookups, _ := srv.Counts(); up != 5 || lookups != 5 {
				t.Fatalf("hashLookup off: uploads %d lookups %d", up, lookups)
			}
		})
	}
}

func TestMetaDefenderDefaultRule(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	md := newMD(srv)
	md.Rule = ""
	f := mdFile("a", "a")
	mustScan(t, md, f) // learns the default rule's name ("File process")
	if h := srv.UploadHeaders; h.Get("rule") != "" {
		t.Fatalf("rule header sent: %v", h)
	}
	if o := mustScan(t, md, f); !o.Files[0].Cached {
		t.Fatal("default rule result not reused")
	}
	// A result of another rule is not reused under the default rule.
	other := newMD(srv)
	other.Rule = "Packages"
	g := mdFile("b", "b")
	mustScan(t, other, g)
	if o := mustScan(t, md, g); o.Files[0].Cached {
		t.Fatal("another rule's result reused for the default rule")
	}
}

func TestMetaDefenderReusable(t *testing.T) {
	var r mdResult
	if err := json.Unmarshal(mdfake.FixtureBytes("in_progress.json"), &r); err != nil {
		t.Fatal(err)
	}
	md := &MetaDefender{Rule: "File process", MaxResultAge: time.Hour}
	r.FileInfo.SHA256 = "ab"
	r.ScanResults.StartTime = time.Now().UTC().Format(time.RFC3339)
	if r.done() || md.reusable(&r, File{SHA256: "ab"}) {
		t.Fatal("an analysis in progress is reusable")
	}
	var ex mdResult
	if err := json.Unmarshal(mdfake.FixtureBytes("spec_example.json"), &ex); err != nil {
		t.Fatal(err)
	}
	if !ex.done() || ex.code() != 20 {
		t.Fatalf("spec example: done %v code %d", ex.done(), ex.code())
	}
	if (&MetaDefender{Rule: "File process", MaxResultAge: 1 << 62}).reusable(&ex, File{SHA256: ex.FileInfo.SHA256}) {
		t.Fatal("result with outdated data is reusable")
	}
	fs, err := mdVerdict(&ex, File{Name: "OPSWAT_Proactive_DLP_CCN.pdf", SHA256: ex.FileInfo.SHA256}, "")
	if err != nil || len(fs) != 1 || fs[0].VulnID != "BLOCKED:Sensitive Data Found" || fs[0].Severity != "critical" ||
		fs[0].Title != "Sensitive Data Found: 0/1 engines" {
		t.Fatalf("spec example verdict: %+v %v", fs, err)
	}
}

func TestMetaDefenderErrors(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.APIKey = "right"
	md := newMD(srv)
	md.APIKey = "wrong"
	if _, err := scanFiles(t, md, mdFile("a", "a")); err == nil || !strings.Contains(err.Error(), "check metadefender.apiKey") ||
		strings.Contains(err.Error(), "wrong") {
		t.Fatalf("bad key: %v", err)
	}

	srv.APIKey = ""
	srv.Do(func(s *mdfake.Server) {
		s.Mutate = func(a *mdfake.Analysis, res map[string]any) {
			res["file_info"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		}
	})
	if _, err := scanFiles(t, newMD(srv), mdFile("a", "a")); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("sha mismatch: %v", err)
	}

	// Content that does not match its recorded digest is never accepted.
	srv.Do(func(s *mdfake.Server) { s.Mutate = nil })
	f := mdFile("b", "b")
	f.SHA256 = strings.Repeat("1", 64)
	md = newMD(srv)
	md.HashLookup = false
	if _, err := scanFiles(t, md, f); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("corrupt blob: %v", err)
	}

	// An unreachable server fails the attempt at once (the job is retried
	// with backoff) instead of waiting for the job's deadline.
	gone := mdfake.New()
	gone.Close()
	start := time.Now()
	if _, err := scanFiles(t, newMD(gone), mdFile("c", "c")); err == nil || !strings.Contains(err.Error(), "upload c to MetaDefender") ||
		time.Since(start) > 2*time.Second {
		t.Fatalf("unreachable: %v after %s", err, time.Since(start))
	}
	if _, err := (&MetaDefender{URL: srv.URL}).Scan(context.Background(), Target{Kind: KindPackage}); err == nil {
		t.Fatal("package target accepted")
	}
}

func TestMetaDefenderConcurrency(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.UploadDelay = 20 * time.Millisecond
	md := newMD(srv)
	md.Concurrency = 2
	var files []File
	for i := 0; i < 8; i++ {
		files = append(files, mdFile(fmt.Sprintf("f%d", i), fmt.Sprintf("content %d", i)))
	}
	o := mustScan(t, md, files...)
	if len(o.Files) != 8 || srv.MaxInflight != 2 {
		t.Fatalf("files %d, max in flight %d", len(o.Files), srv.MaxInflight)
	}
}

// Concurrent scans of the same content (two jobs, one shared file) upload
// it once.
func TestMetaDefenderSharedAnalysis(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.PollsBeforeDone = 5
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := scanFiles(t, newMD(srv), mdFile("shared", "shared layer"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if up, _, _ := srv.Counts(); up != 1 {
		t.Fatalf("uploads: %d", up)
	}
}

func TestMetaDefenderCheck(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	md := newMD(srv)
	md.Rule = "Packages"
	h, err := md.Check(context.Background())
	if err != nil || h.Version != "5.24.2" || h.Rules["Packages"] != 1<<30 {
		t.Fatalf("check: %+v %v", h, err)
	}
	md.Rule = "Nope"
	if _, err := md.Check(context.Background()); err == nil || !strings.Contains(err.Error(), `rule "Nope" is not available`) ||
		!strings.Contains(err.Error(), "File process, Packages") {
		t.Fatalf("unknown rule: %v", err)
	}
	srv.Do(func(s *mdfake.Server) { s.Down = true })
	if _, err := md.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("down: %v", err)
	}
}

func TestEncodeHeader(t *testing.T) {
	for in, want := range map[string]string{
		"File process":             "File%20process",
		"pkg_1.0-1.tgz":            "pkg_1.0-1.tgz",
		"foo_1.0+dfsg-1_amd64.deb": "foo_1.0%2Bdfsg-1_amd64.deb",
		"Règle":                    "R%C3%A8gle",
		"a\r\nX-Injected: 1":       "a%0D%0AX-Injected%3A%201",
		"report (final) #2 & more": "report%20%28final%29%20%232%20%26%20more",
	} {
		if got := encodeHeader(in); got != want {
			t.Errorf("encodeHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLeafPath(t *testing.T) {
	for _, c := range [][3]string{
		{`tool.zip\bin\x.exe`, "tool.zip", "bin/x.exe"},
		{`other.zip\x.exe`, "tool.zip", "other.zip/x.exe"},
		{"x.exe", "tool.zip", "x.exe"},
	} {
		if got := leafPath(c[0], c[1]); got != c[2] {
			t.Errorf("leafPath(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestFindingKind(t *testing.T) {
	for id, want := range map[string]string{"CVE-2024-1": "vulnerability", "GHSA-x": "vulnerability",
		"MALWARE:x": "malware", "SUSPICIOUS:y": "malware", "PUA:z": "malware", "BLOCKED:Encrypted Archive": "policy"} {
		if got := FindingKind(id); got != want {
			t.Errorf("FindingKind(%q) = %q, want %q", id, got, want)
		}
	}
	if IsThreat("CVE-1") || !IsThreat("BLOCKED:x") {
		t.Fatal("IsThreat")
	}
}
