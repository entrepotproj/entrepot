// Package gitlab is a minimal GitLab REST API (v4) client used to report
// scan results back to CI pipelines: commit statuses and merge request
// notes.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client calls one GitLab instance with a PRIVATE-TOKEN.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a client for the instance at baseURL (e.g. https://gitlab.example.com).
func New(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: hc}
}

// Error is a non-2xx API response.
type Error struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *Error) Error() string {
	return fmt.Sprintf("gitlab %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// project encodes a numeric id or a namespaced path.
func project(p string) string { return url.PathEscape(p) }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) (*http.Response, error) {
	u := c.BaseURL + "/api/v4" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", c.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return resp, &Error{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
			return resp, fmt.Errorf("gitlab %s %s: decode: %w", method, path, err)
		}
	}
	return resp, nil
}

// CommitStatus is the body of POST /projects/:id/statuses/:sha.
type CommitStatus struct {
	// State is pending, running, success, failed or canceled.
	State       string `json:"state"`
	Name        string `json:"name,omitempty"`
	Ref         string `json:"ref,omitempty"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	PipelineID  int64  `json:"pipeline_id,omitempty"`
}

// SetCommitStatus creates or updates the commit status named st.Name.
func (c *Client) SetCommitStatus(ctx context.Context, projectID, sha string, st CommitStatus) error {
	if len(st.Description) > 255 {
		st.Description = st.Description[:252] + "..."
	}
	_, err := c.do(ctx, http.MethodPost, "/projects/"+project(projectID)+"/statuses/"+url.PathEscape(sha), nil, st, nil)
	return err
}

// MergeRequest is the subset of a merge request used here.
type MergeRequest struct {
	ID        int64  `json:"id"`
	IID       int64  `json:"iid"`
	ProjectID int64  `json:"project_id"`
	State     string `json:"state"`
	WebURL    string `json:"web_url"`
}

// CommitMergeRequests lists merge requests associated with a commit.
func (c *Client) CommitMergeRequests(ctx context.Context, projectID, sha string) ([]MergeRequest, error) {
	var out []MergeRequest
	_, err := c.do(ctx, http.MethodGet, "/projects/"+project(projectID)+"/repository/commits/"+url.PathEscape(sha)+"/merge_requests",
		nil, nil, &out)
	return out, err
}

// Note is a merge request comment.
type Note struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	System bool   `json:"system"`
}

// MergeRequestNotes lists the notes of a merge request (up to 20 pages of 100).
func (c *Client) MergeRequestNotes(ctx context.Context, projectID string, iid int64) ([]Note, error) {
	var all []Note
	for page := 1; page <= 20; page++ {
		var out []Note
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}, "sort": {"asc"}, "order_by": {"created_at"}}
		resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/projects/%s/merge_requests/%d/notes", project(projectID), iid), q, nil, &out)
		if err != nil {
			return nil, err
		}
		all = append(all, out...)
		next := resp.Header.Get("X-Next-Page")
		if next == "" || len(out) == 0 {
			break
		}
	}
	return all, nil
}

// CreateMergeRequestNote adds a note.
func (c *Client) CreateMergeRequestNote(ctx context.Context, projectID string, iid int64, body string) (*Note, error) {
	var n Note
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/projects/%s/merge_requests/%d/notes", project(projectID), iid),
		nil, map[string]string{"body": body}, &n)
	return &n, err
}

// UpdateMergeRequestNote replaces a note's body.
func (c *Client) UpdateMergeRequestNote(ctx context.Context, projectID string, iid, noteID int64, body string) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", project(projectID), iid, noteID),
		nil, map[string]string{"body": body}, nil)
	return err
}

// UpsertMergeRequestNote updates the note containing marker, or creates
// one. It reports whether a note was created.
func (c *Client) UpsertMergeRequestNote(ctx context.Context, projectID string, iid int64, marker, body string) (bool, error) {
	notes, err := c.MergeRequestNotes(ctx, projectID, iid)
	if err != nil {
		return false, err
	}
	for _, n := range notes {
		if !n.System && strings.Contains(n.Body, marker) {
			if n.Body == body {
				return false, nil
			}
			return false, c.UpdateMergeRequestNote(ctx, projectID, iid, n.ID, body)
		}
	}
	_, err = c.CreateMergeRequestNote(ctx, projectID, iid, body)
	return err == nil, err
}
