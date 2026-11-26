// Package mdfake is a fake OPSWAT MetaDefender Core REST API for tests.
// Its responses are built from fixtures that follow the MetaDefender Core
// 5.x OpenAPI schemas (fixtures/; capture.sh records the same responses from
// a real server to compare).
//
// The verdict for an uploaded file is chosen by markers in its content, so
// tests never need real malware:
//
//	X-MDFAKE-MALWARE     Blocked, Infected (1), threat "Virus eicar test file"
//	X-MDFAKE-SUSPICIOUS  Blocked, Suspicious (2)
//	X-MDFAKE-PUA         Blocked, Potentially Unwanted (22)
//	X-MDFAKE-ALLOWED-PUA Allowed, Potentially Unwanted (22)
//	X-MDFAKE-ARCHIVE     Blocked, Infected (1) inside an archive (blocked-leaves lists the child)
//	X-MDFAKE-ENCRYPTED   Blocked, Encrypted Archive (12)
//	X-MDFAKE-FAIL        Allowed, Failed (3)
//
// Anything else is Allowed, No Threat Detected (0).
package mdfake

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// Fixture returns a fixture decoded as generic JSON.
func Fixture(name string) map[string]any {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		panic(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return v
}

// FixtureBytes returns a fixture's raw content.
func FixtureBytes(name string) []byte {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		panic(err)
	}
	return b
}

// Analysis is one analysis held by the server.
type Analysis struct {
	DataID   string
	Name     string
	SHA256   string
	Size     int64
	Rule     string
	Started  time.Time
	Polls    int // polls answered "in progress" so far
	Result   map[string]any
	Leaves   map[string]any
	Canceled bool
}

// Server is a fake MetaDefender Core.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// APIKey, when set, is required in the apikey header.
	APIKey string
	// Busy makes the next N uploads answer 503 (queue full).
	Busy int
	// AlwaysBusy makes every upload answer 503.
	AlwaysBusy bool
	// PollsBeforeDone is the number of result polls answered "in
	// progress" before the result is final (default 1).
	PollsBeforeDone int
	// Never makes analyses never finish.
	Never bool
	// Down makes every request answer 503 (readyz unhealthy).
	Down bool
	// Broken makes every request answer 500.
	Broken bool
	// Rules available (default "File process" and "Packages").
	Rules []string
	// DefaultRule is the profile of uploads without a rule header.
	DefaultRule string
	// UploadDelay delays upload responses.
	UploadDelay time.Duration
	// HashNotFound404 answers unknown hashes with 404 instead of 200
	// {"<HASH>": "Not Found"}.
	HashNotFound404 bool
	// Mutate, when set, edits each final result before it is returned.
	Mutate func(a *Analysis, result map[string]any)

	analyses map[string]*Analysis
	byHash   map[string]*Analysis // latest finished, per sha256 and rule

	Uploads, Lookups, Polls int
	inflight, MaxInflight   int
	// UploadHeaders are the headers of the last upload.
	UploadHeaders http.Header
	// Requests counts requests per "METHOD /path" (data ids replaced by {id}).
	Requests map[string]int
}

// New starts a fake server.
func New() *Server {
	s := &Server{PollsBeforeDone: 1, DefaultRule: "File process", analyses: map[string]*Analysis{},
		byHash: map[string]*Analysis{}, Requests: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Do runs fn with the server locked (to change settings while serving).
func (s *Server) Do(fn func(s *Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// Analyses returns the analyses held, in no particular order.
func (s *Server) Analyses() []*Analysis {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Analysis, 0, len(s.analyses))
	for _, a := range s.analyses {
		out = append(out, a)
	}
	return out
}

// Counts returns uploads, hash lookups and result polls so far.
func (s *Server) Counts() (uploads, lookups, polls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Uploads, s.Lookups, s.Polls
}

// Forget drops every analysis (as if the server's history was purged).
func (s *Server) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analyses = map[string]*Analysis{}
	s.byHash = map[string]*Analysis{}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	key := r.Method + " " + path
	if strings.HasPrefix(path, "/file/") && path != "/file/rules" {
		parts := strings.Split(path, "/")
		parts[2] = "{id}"
		key = r.Method + " " + strings.Join(parts, "/")
	} else if strings.HasPrefix(path, "/hash/") {
		key = r.Method + " /hash/{hash}"
	}
	s.mu.Lock()
	s.Requests[key]++
	down, broken, apiKey := s.Down, s.Broken, s.APIKey
	s.mu.Unlock()
	if down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if broken {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"err": "Internal server error"})
		return
	}
	if apiKey != "" && r.Header.Get("apikey") != apiKey && path != "/readyz" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"err": "Invalid API key"})
		return
	}
	switch {
	case r.Method == http.MethodPost && path == "/file":
		s.upload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/hash/"):
		s.lookup(w, r, strings.TrimPrefix(path, "/hash/"))
	case r.Method == http.MethodGet && path == "/file/rules":
		s.mu.Lock()
		rules := s.Rules
		s.mu.Unlock()
		if rules == nil {
			_, _ = w.Write(FixtureBytes("rules.json"))
			return
		}
		var out []map[string]any
		for _, n := range rules {
			out = append(out, map[string]any{"name": n, "max_file_size": 200 << 20})
		}
		writeJSON(w, http.StatusOK, out)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/blocked-leaves"):
		s.leaves(w, strings.TrimSuffix(strings.TrimPrefix(path, "/file/"), "/blocked-leaves"))
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/cancel"):
		s.cancel(w, strings.TrimSuffix(strings.TrimPrefix(path, "/file/"), "/cancel"))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/file/"):
		s.result(w, strings.TrimPrefix(path, "/file/"))
	case r.Method == http.MethodGet && path == "/version":
		_, _ = w.Write(FixtureBytes("version.json"))
	case r.Method == http.MethodGet && path == "/readyz":
		_, _ = w.Write(FixtureBytes("readyz.json"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Length") == "" && r.ContentLength < 0 {
		writeJSON(w, http.StatusLengthRequired, map[string]string{"err": "Content-Length header is missing"})
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); strings.HasPrefix(mt, "multipart/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"err": "this fake only accepts raw bodies"})
		return
	}
	s.mu.Lock()
	s.inflight++
	if s.inflight > s.MaxInflight {
		s.MaxInflight = s.inflight
	}
	busy := s.AlwaysBusy || s.Busy > 0
	if s.Busy > 0 {
		s.Busy--
	}
	delay := s.UploadDelay
	s.UploadHeaders = r.Header.Clone()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	if delay > 0 {
		time.Sleep(delay)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	if busy {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(FixtureBytes("busy.json"))
		return
	}
	if len(body) == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"err": "Body input is empty"})
		return
	}
	sum := sha256.Sum256(body)
	name := r.Header.Get("filename")
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	rule := r.Header.Get("rule")
	if n, err := url.PathUnescape(rule); err == nil {
		rule = n
	}
	s.mu.Lock()
	if rule == "" {
		rule = s.DefaultRule
	}
	known := s.Rules
	if known == nil {
		known = []string{"File process", "Packages"}
	}
	s.mu.Unlock()
	found := false
	for _, k := range known {
		found = found || k == rule
	}
	if !found {
		writeJSON(w, http.StatusBadRequest, map[string]string{"err": "Invalid rule: " + rule})
		return
	}
	a := &Analysis{DataID: newID(), Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		Rule: rule, Started: time.Now()}
	a.Result, a.Leaves = verdictFor(a, body)
	s.mu.Lock()
	s.Uploads++
	s.analyses[a.DataID] = a
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(bytes.ReplaceAll(FixtureBytes("upload.json"), []byte("00000000000000000000000000000000"), []byte(a.DataID)))
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

// threat sets every engine's verdict.
func threat(res map[string]any, code int, names ...string) {
	details := res["scan_results"].(map[string]any)["scan_details"].(map[string]any)
	i := 0
	for _, eng := range []string{"Avira", "ClamAV", "K7"} {
		d := details[eng].(map[string]any)
		if i < len(names) && names[i] != "" {
			d["scan_result_i"] = code
			d["threat_found"] = names[i]
		}
		i++
	}
}

func verdictFor(a *Analysis, body []byte) (map[string]any, map[string]any) {
	res := Fixture("analysis.json")
	res["data_id"] = a.DataID
	setPath(res, "scan_results.data_id", a.DataID)
	setPath(res, "file_info.sha256", a.SHA256)
	setPath(res, "file_info.display_name", a.Name)
	setPath(res, "file_info.file_size", a.Size)
	setPath(res, "process_info.profile", a.Rule)
	setPath(res, "scan_results.start_time", a.Started.UTC().Format("2006-01-02T15:04:05.000Z"))
	block := func(code int, label string, reasons ...string) {
		setPath(res, "process_info.result", "Blocked")
		setPath(res, "process_info.blocked_reason", strings.Join(reasons, ", "))
		setPath(res, "process_info.blocked_reasons", reasons)
		setPath(res, "process_info.verdicts", reasons)
		setPath(res, "scan_results.scan_all_result_i", code)
		setPath(res, "scan_results.scan_all_result_a", label)
	}
	var leaves map[string]any
	switch {
	case bytes.Contains(body, []byte("X-MDFAKE-MALWARE")):
		block(1, "Infected", "Infected")
		setPath(res, "scan_results.current_av_result_i", 1)
		threat(res, 1, "Virus eicar test file", "Win.Test.EICAR_HDB-1", "Virus eicar test file")
	case bytes.Contains(body, []byte("X-MDFAKE-SUSPICIOUS")):
		block(2, "Suspicious", "Suspicious")
		threat(res, 2, "Heuristic.Packed")
	case bytes.Contains(body, []byte("X-MDFAKE-ALLOWED-PUA")):
		setPath(res, "scan_results.scan_all_result_i", 22)
		setPath(res, "scan_results.scan_all_result_a", "Potentially Unwanted")
		threat(res, 22, "", "PUA.Win.Adware.Generic")
	case bytes.Contains(body, []byte("X-MDFAKE-PUA")):
		block(22, "Potentially Unwanted", "Potentially Unwanted")
		threat(res, 22, "", "PUA.Win.Adware.Generic")
	case bytes.Contains(body, []byte("X-MDFAKE-ARCHIVE")):
		block(1, "Infected", "Infected")
		setPath(res, "scan_results.current_av_result_i", 0)
		threat(res, 1, "Virus eicar test file", "Win.Test.EICAR_HDB-1", "Virus eicar test file")
		leaves = Fixture("blocked_leaves.json")
		d := leaves["details"].([]any)[0].(map[string]any)
		d["parent_id"] = a.DataID
		d["path"] = a.Name + `\bin\payload.exe`
	case bytes.Contains(body, []byte("X-MDFAKE-ENCRYPTED")):
		block(12, "Encrypted Archive", "Encrypted Archive")
	case bytes.Contains(body, []byte("X-MDFAKE-FAIL")):
		setPath(res, "scan_results.scan_all_result_i", 3)
		setPath(res, "scan_results.scan_all_result_a", "Failed")
	}
	return res, leaves
}

// final returns the result of an analysis, or the in-progress fixture.
func (s *Server) final(a *Analysis, countPoll bool) map[string]any {
	if a.Canceled {
		res := copyJSON(a.Result)
		setPath(res, "scan_results.scan_all_result_i", 19)
		setPath(res, "scan_results.scan_all_result_a", "Cancelled")
		return res
	}
	if s.Never || a.Polls < s.PollsBeforeDone {
		if countPoll {
			a.Polls++
		}
		p := Fixture("in_progress.json")
		p["data_id"] = a.DataID
		setPath(p, "scan_results.data_id", a.DataID)
		setPath(p, "file_info.sha256", a.SHA256)
		setPath(p, "process_info.profile", a.Rule)
		return p
	}
	res := copyJSON(a.Result)
	if s.Mutate != nil {
		s.Mutate(a, res)
	}
	return res
}

func copyJSON(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Server) result(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Polls++
	a := s.analyses[id]
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]string{id: "Not Found"})
		return
	}
	res := s.final(a, true)
	if pi, _ := res["process_info"].(map[string]any); pi != nil && pi["result"] != "Processing" {
		s.byHash[a.SHA256+"\x00"+a.Rule] = a
		s.byHash[a.SHA256] = a
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Lookups++
	hash = strings.ToLower(hash)
	// Like MetaDefender, the latest finished analysis of the hash is
	// returned, whatever its rule.
	a := s.byHash[hash]
	if a == nil {
		if s.HashNotFound404 {
			writeJSON(w, http.StatusNotFound, map[string]string{"err": "Not Found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{strings.ToUpper(hash): "Not Found"})
		return
	}
	writeJSON(w, http.StatusOK, s.final(a, false))
}

func (s *Server) leaves(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.analyses[id]
	if a == nil {
		http.NotFound(w, nil)
		return
	}
	l := a.Leaves
	if l == nil {
		l = map[string]any{"details": []any{}, "limit_reached": false}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_ = json.NewEncoder(w).Encode(l)
}

func (s *Server) cancel(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.analyses[id]
	if a == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	a.Canceled = true
	writeJSON(w, http.StatusOK, map[string]string{id: "cancelled"})
}

// Canceled lists the data ids of cancelled analyses.
func (s *Server) Canceled() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, a := range s.analyses {
		if a.Canceled {
			out = append(out, id)
		}
	}
	return out
}
