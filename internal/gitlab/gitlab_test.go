package gitlab_test

import (
	"context"
	"strings"
	"testing"

	"github.com/entrepotproj/entrepot/internal/gitlab"
	"github.com/entrepotproj/entrepot/internal/gitlab/gitlabtest"
)

func TestClient(t *testing.T) {
	fake := gitlabtest.New(t, "secret-token")
	fake.AddMergeRequest("group/app", "abc123", 7)
	// Notes from others (and pagination) must be preserved.
	for i := 0; i < 120; i++ {
		fake.AddNote(7, "unrelated comment")
	}
	c := gitlab.New(fake.URL, "secret-token", nil)
	ctx := context.Background()

	if err := c.SetCommitStatus(ctx, "group/app", "abc123", gitlab.CommitStatus{State: "failed", Name: "entrepot/scan/npm",
		Description: strings.Repeat("x", 300), PipelineID: 9}); err != nil {
		t.Fatal(err)
	}
	st := fake.Statuses()
	if len(st) != 1 || st[0].Project != "group/app" || st[0].SHA != "abc123" || st[0].Status.State != "failed" ||
		len(st[0].Status.Description) != 255 || st[0].Status.PipelineID != 9 {
		t.Fatalf("statuses = %+v", st)
	}
	mrs, err := c.CommitMergeRequests(ctx, "group/app", "abc123")
	if err != nil || len(mrs) != 1 || mrs[0].IID != 7 {
		t.Fatalf("mrs = %+v %v", mrs, err)
	}
	created, err := c.UpsertMergeRequestNote(ctx, "group/app", 7, "<!-- m -->", "<!-- m -->\nfirst")
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	created, err = c.UpsertMergeRequestNote(ctx, "group/app", 7, "<!-- m -->", "<!-- m -->\nsecond")
	if err != nil || created {
		t.Fatalf("update: %v %v", created, err)
	}
	notes := fake.Notes(7)
	n := 0
	for _, b := range notes {
		if strings.Contains(b, "<!-- m -->") {
			n++
			if !strings.HasSuffix(b, "second") {
				t.Errorf("note not updated: %q", b)
			}
		}
	}
	if n != 1 || len(notes) != 121 {
		t.Fatalf("notes: %d marked of %d", n, len(notes))
	}
	// Wrong token.
	bad := gitlab.New(fake.URL, "nope", nil)
	if err := bad.SetCommitStatus(ctx, "1", "abc", gitlab.CommitStatus{State: "success"}); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
}
