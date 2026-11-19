package docker

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

var _ format.Cleaner = (*Handler)(nil)

// imageAssets groups one image's assets by kind.
type imageAssets struct {
	tags      []*store.Asset
	manifests map[string]*store.Asset // digest -> asset
	blobs     map[string]*store.Asset
}

// CleanupCandidates implements format.Cleaner for untaggedOlderThanDays:
//
//   - manifests (_manifests/{digest}) older than the cut-off that are not
//     reachable from a tag or from a manifest newer than the cut-off
//     (through index children and OCI referrer subjects), and
//   - blob links (_blobs/{digest}) older than the cut-off that no
//     remaining manifest references (config, layers, index blobs).
//
// Manifests that cannot be parsed are kept, and then no blob of that image
// is removed. Only the repository's own assets are considered (groups
// have none).
func (h *Handler) CleanupCandidates(ctx context.Context, rp *repo.Repository, c format.CleanupCriteria) ([]*store.Asset, error) {
	if c.UntaggedOlderThan <= 0 || rp.IsGroup() {
		return nil, nil
	}
	cutoff := time.Now().Add(-c.UntaggedOlderThan)
	images := map[string]*imageAssets{}
	var order []string
	get := func(image string) *imageAssets {
		ia, ok := images[image]
		if !ok {
			ia = &imageAssets{manifests: map[string]*store.Asset{}, blobs: map[string]*store.Asset{}}
			images[image] = ia
			order = append(order, image)
		}
		return ia
	}
	after := ""
	for {
		batch, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, "", after, 1000)
		if err != nil {
			return nil, err
		}
		for _, a := range batch {
			image, kind, rest, ok := splitAssetPath(a.Path)
			if !ok {
				continue
			}
			ia := get(image)
			switch kind {
			case "_tags":
				ia.tags = append(ia.tags, a)
			case "_manifests":
				ia.manifests[rest] = a
			case "_blobs":
				ia.blobs[rest] = a
			}
		}
		if len(batch) < 1000 {
			break
		}
		after = batch[len(batch)-1].Path
	}

	var out []*store.Asset
	for _, image := range order {
		cands, err := h.imageCandidates(ctx, rp, images[image], cutoff)
		if err != nil {
			return nil, err
		}
		out = append(out, cands...)
	}
	return out, nil
}

func (h *Handler) imageCandidates(ctx context.Context, rp *repo.Repository, ia *imageAssets, cutoff time.Time) ([]*store.Asset, error) {
	docs := map[string]*manifestDoc{}
	unparsable := false
	parse := func(d string) *manifestDoc {
		if doc, ok := docs[d]; ok {
			return doc
		}
		a := ia.manifests[d]
		var doc *manifestDoc
		if a != nil {
			b, err := h.env.Repos.ReadAll(ctx, rp, a, MaxManifest)
			var m manifestDoc
			if err == nil && json.Unmarshal(b, &m) == nil {
				doc = &m
			} else {
				unparsable = true
			}
		}
		docs[d] = doc
		return doc
	}

	// Roots: tagged manifests and manifests newer than the cut-off.
	keep := map[string]bool{}
	var queue []string
	mark := func(d string) {
		if _, ok := ia.manifests[d]; ok && !keep[d] {
			keep[d] = true
			queue = append(queue, d)
		}
	}
	for _, t := range ia.tags {
		mark(t.Digest)
	}
	for d, a := range ia.manifests {
		if !a.CreatedAt.Before(cutoff) {
			mark(d)
		}
	}
	// Referrers (manifests whose subject is d) are kept with their subject.
	subjects := map[string][]string{}
	for d := range ia.manifests {
		if doc := parse(d); doc != nil && doc.Subject != nil {
			subjects[doc.Subject.Digest] = append(subjects[doc.Subject.Digest], d)
		}
	}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if doc := parse(d); doc != nil {
			for _, child := range doc.Manifests {
				mark(child.Digest)
			}
		}
		for _, ref := range subjects[d] {
			mark(ref)
		}
	}

	var out []*store.Asset
	for d, a := range ia.manifests {
		if !keep[d] {
			out = append(out, a)
		}
	}
	if unparsable {
		return out, nil
	}
	// Blobs referenced by the remaining manifests.
	used := map[string]bool{}
	for d := range keep {
		doc := docs[d]
		if doc == nil {
			continue
		}
		if doc.Config != nil {
			used[doc.Config.Digest] = true
		}
		for _, l := range doc.Layers {
			used[l.Digest] = true
		}
		for _, m := range doc.Manifests {
			used[m.Digest] = true
		}
	}
	for d, a := range ia.blobs {
		if !used[d] && a.CreatedAt.Before(cutoff) {
			out = append(out, a)
		}
	}
	return out, nil
}

// splitAssetPath splits "{image}/_kind/{rest}".
func splitAssetPath(p string) (image, kind, rest string, ok bool) {
	for _, k := range []string{"_tags", "_manifests", "_blobs"} {
		if i := strings.Index(p, "/"+k+"/"); i > 0 {
			return p[:i], k, p[i+len(k)+2:], true
		}
	}
	return "", "", "", false
}
