// Package gitlabtest is a fake GitLab REST API for tests: commit statuses,
// merge requests of a commit and merge request notes.
package gitlabtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/geoffo-dev/package-repository/internal/gitlab"
)

// Status is a recorded commit status.
type Status struct {
	Project string
	SHA     string
	Status  gitlab.CommitStatus
}

type note struct {
	ID   int64
	Body string
}

// Server is the fake API.
type Server struct {
	*httptest.Server
	token string

	mu       sync.Mutex
	statuses []Status
	mrs      map[string][]int64 // project + "@" + sha -> MR iids
	notes    map[int64][]note
	nextID   int64
	Updates  int
	Creates  int
}

// New starts a fake GitLab that accepts PRIVATE-TOKEN token.
func New(t *testing.T, token string) *Server {
	s := &Server{token: token, mrs: map[string][]int64{}, notes: map[int64][]note{}, nextID: 1}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// AddMergeRequest associates MR iid (in project) with commit sha.
func (s *Server) AddMergeRequest(project, sha string, iid int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := project + "@" + sha
	s.mrs[k] = append(s.mrs[k], iid)
}

// AddNote adds a note to MR iid.
func (s *Server) AddNote(iid int64, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes[iid] = append(s.notes[iid], note{ID: s.nextID, Body: body})
	s.nextID++
}

// Statuses returns recorded commit statuses.
func (s *Server) Statuses() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Status(nil), s.statuses...)
}

// Notes returns the bodies of MR iid's notes.
func (s *Server) Notes(iid int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.notes[iid] {
		out = append(out, n.Body)
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("PRIVATE-TOKEN") != s.token {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "401 Unauthorized"})
		return
	}
	// /api/v4/projects/{id}/...
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v4/projects/")
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	project, _ := url.PathUnescape(parts[0])
	rest := parts[1:]
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && len(rest) == 2 && rest[0] == "statuses":
		var st gitlab.CommitStatus
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil || st.State == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "state is missing"})
			return
		}
		s.statuses = append(s.statuses, Status{Project: project, SHA: rest[1], Status: st})
		writeJSON(w, http.StatusCreated, map[string]any{"id": len(s.statuses), "status": st.State, "name": st.Name})
	case r.Method == http.MethodGet && len(rest) == 4 && rest[0] == "repository" && rest[3] == "merge_requests":
		pid, _ := strconv.ParseInt(project, 10, 64)
		var out []gitlab.MergeRequest
		for _, iid := range s.mrs[project+"@"+rest[2]] {
			out = append(out, gitlab.MergeRequest{ID: 1000 + iid, IID: iid, ProjectID: pid, State: "opened"})
		}
		if out == nil {
			out = []gitlab.MergeRequest{}
		}
		writeJSON(w, http.StatusOK, out)
	case len(rest) >= 3 && rest[0] == "merge_requests" && rest[2] == "notes":
		iid, _ := strconv.ParseInt(rest[1], 10, 64)
		switch {
		case r.Method == http.MethodGet && len(rest) == 3:
			per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if per <= 0 {
				per = 20
			}
			if page <= 0 {
				page = 1
			}
			all := s.notes[iid]
			start, end := (page-1)*per, page*per
			if start > len(all) {
				start = len(all)
			}
			if end >= len(all) {
				end = len(all)
			} else {
				w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
			}
			out := []map[string]any{}
			for _, n := range all[start:end] {
				out = append(out, map[string]any{"id": n.ID, "body": n.Body, "system": false})
			}
			writeJSON(w, http.StatusOK, out)
		case r.Method == http.MethodPost && len(rest) == 3:
			var in struct{ Body string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			n := note{ID: s.nextID, Body: in.Body}
			s.nextID++
			s.notes[iid] = append(s.notes[iid], n)
			s.Creates++
			writeJSON(w, http.StatusCreated, map[string]any{"id": n.ID, "body": n.Body})
		case r.Method == http.MethodPut && len(rest) == 4:
			id, _ := strconv.ParseInt(rest[3], 10, 64)
			var in struct{ Body string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			for i := range s.notes[iid] {
				if s.notes[iid][i].ID == id {
					s.notes[iid][i].Body = in.Body
					s.Updates++
					writeJSON(w, http.StatusOK, map[string]any{"id": id, "body": in.Body})
					return
				}
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}
