package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm shasum
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

var (
	errVersionExists = errors.New("cannot publish over a previously published version (redeploy is disabled for this repository)")
	errRevConflict   = errors.New("document revision conflict: refetch the package and retry")
)

// reservedFields are managed by Entrepot and never copied from clients.
var reservedFields = map[string]bool{
	"_id": true, "_rev": true, "_attachments": true, "versions": true, "dist-tags": true, "time": true,
	"access": true, "_revisions": true, "users": true, "name": true,
}

// publishRequest is the JSON body of PUT /{package}.
type publishRequest struct {
	Name        string                                `json:"name"`
	Rev         string                                `json:"_rev"`
	DistTags    map[string]string                     `json:"dist-tags"`
	Versions    map[string]map[string]json.RawMessage `json:"versions"`
	Attachments map[string]struct {
		Data   string `json:"data"`
		Length int64  `json:"length"`
	} `json:"_attachments"`
}

func (h *Handler) putPackument(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, rev string) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPublish))
	if err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, "request too large or unreadable: "+err.Error())
		return
	}
	var req publishRequest
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid package document: "+err.Error())
		return
	}
	_ = json.Unmarshal(b, &raw)
	b = nil //nolint:ineffassign,wastedassign // allow the body to be collected
	if req.Name != "" && req.Name != name {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("package name %q does not match the URL (%q)", req.Name, name))
		return
	}
	if len(req.Attachments) == 0 {
		if rev == "" {
			rev = req.Rev
		}
		h.updatePackument(w, r, rp, name, rev, &req, raw)
		return
	}
	in := publishInput{
		Name:     name,
		Versions: req.Versions,
		Files:    map[string][]byte{},
		DistTags: req.DistTags,
		Fields:   raw,
		Actor:    format.Actor(r),
	}
	for file, att := range req.Attachments {
		data, err := base64.StdEncoding.DecodeString(att.Data)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "attachment "+file+" is not valid base64")
			return
		}
		if att.Length > 0 && att.Length != int64(len(data)) {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("attachment %s: length %d does not match data (%d bytes)", file, att.Length, len(data)))
			return
		}
		in.Files[path.Base(file)] = data
	}
	pk, err := h.publish(r.Context(), rp, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "success": true, "id": name, "rev": pk.str("_rev")})
}

type publishInput struct {
	Name     string
	Versions map[string]map[string]json.RawMessage
	// Files maps tarball file names to content.
	Files    map[string][]byte
	DistTags map[string]string
	// Fields are top-level packument fields supplied by the client.
	Fields map[string]json.RawMessage
	Actor  string
}

// publish adds new versions (with their tarballs) to a hosted package.
func (h *Handler) publish(ctx context.Context, rp *repo.Repository, in publishInput) (*packument, error) {
	name := in.Name
	if !newNameRe.MatchString(name) || len(name) > 214 {
		return nil, format.BadRequest("invalid package name %q (names must be lowercase and URL-safe)", name)
	}
	if len(in.Versions) == 0 {
		return nil, format.BadRequest("no versions to publish")
	}
	unlock := h.lock(rp, name)
	defer unlock()

	pk, _, err := h.hostedPackument(ctx, rp, name)
	if errors.Is(err, repo.ErrNotFound) {
		pk, err = newPackument(name), nil
	}
	if err != nil {
		return nil, err
	}
	oldTags := copyTags(pk.DistTags)
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	versions := make([]string, 0, len(in.Versions))
	for v := range in.Versions {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return compareSemver(versions[i], versions[j]) < 0 })
	for _, version := range versions {
		man := in.Versions[version]
		if err := validVersion(version); err != nil {
			return nil, err
		}
		if rawStr(man, "name") != name || rawStr(man, "version") != version {
			return nil, format.BadRequest("manifest of %s must have name %q and version %q", version, name, version)
		}
		if _, exists := pk.Versions[version]; exists && !rp.AllowRedeploy() {
			return nil, fmt.Errorf("%w: %s@%s", errVersionExists, name, version)
		}
		file := tarballFile(name, version, man)
		data, ok := in.Files[file]
		if !ok && len(in.Files) == 1 && len(in.Versions) == 1 {
			for f, d := range in.Files {
				file, data, ok = f, d, true
			}
		}
		if !ok {
			return nil, format.BadRequest("no tarball attachment for %s@%s", name, version)
		}
		if !validFile(file) || !strings.HasSuffix(file, ".tgz") {
			return nil, format.BadRequest("invalid tarball name %q", file)
		}
		if err := h.storeVersion(ctx, rp, name, version, file, man, data, in.Actor); err != nil {
			return nil, err
		}
		pk.Versions[version] = man
		pk.Time[version] = marshal(now)
	}
	if _, ok := pk.Time["created"]; !ok {
		pk.Time["created"] = marshal(now)
	}
	pk.Time["modified"] = marshal(now)
	for t, v := range in.DistTags {
		if _, ok := pk.Versions[v]; ok && tagRe.MatchString(t) {
			pk.DistTags[t] = v
		}
	}
	if _, ok := pk.DistTags["latest"]; !ok {
		pk.DistTags["latest"] = pk.highest()
	}
	for k, v := range in.Fields {
		if !reservedFields[k] && !strings.HasPrefix(k, "_") {
			pk.Fields[k] = v
		}
	}
	// Top-level metadata follows the latest version.
	if latest, ok := pk.Versions[pk.DistTags["latest"]]; ok {
		for _, k := range []string{"description", "keywords", "license", "author", "homepage", "repository", "bugs", "maintainers"} {
			if v, ok := latest[k]; ok {
				pk.Fields[k] = v
			}
		}
		if readme, ok := latest["readme"]; ok {
			if _, given := in.Fields["readme"]; !given {
				pk.Fields["readme"] = readme
			}
		}
	}
	if err := h.savePackument(ctx, rp, name, pk, in.Actor); err != nil {
		return nil, err
	}
	h.syncTagAttrs(ctx, rp, name, oldTags, pk.DistTags)
	return pk, nil
}

func validVersion(v string) error {
	if v == "" || len(v) > 256 || !validFile(v) || strings.ContainsAny(v, " \t") || v[0] == '-' {
		return format.BadRequest("invalid version %q", v)
	}
	return nil
}

// storeVersion completes a version manifest's dist fields and stores its
// tarball.
func (h *Handler) storeVersion(ctx context.Context, rp *repo.Repository, name, version, file string, man map[string]json.RawMessage, data []byte, actor string) error {
	s1 := sha1.Sum(data) //nolint:gosec
	s512 := sha512.Sum512(data)
	shasum := hex.EncodeToString(s1[:])
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
	d := dist(man)
	if given := rawStr(d, "shasum"); given != "" && !strings.EqualFold(given, shasum) {
		return format.BadRequest("dist.shasum of %s@%s does not match the tarball", name, version)
	}
	for _, part := range strings.Fields(rawStr(d, "integrity")) {
		if strings.HasPrefix(part, "sha512-") && part != integrity {
			return format.BadRequest("dist.integrity of %s@%s does not match the tarball", name, version)
		}
	}
	newDist := map[string]json.RawMessage{
		"shasum":    marshal(shasum),
		"integrity": marshal(integrity),
		"tarball":   marshal(tarballPath(name, file)),
	}
	for _, k := range []string{"fileCount", "unpackedSize"} {
		if v, ok := d[k]; ok {
			newDist[k] = v
		}
	}
	man["dist"] = marshal(newDist)
	man["_id"] = marshal(name + "@" + version)
	if hasInstallScript(man) {
		man["hasInstallScript"] = json.RawMessage("true")
	}
	attrs := marshal(map[string]string{"integrity": integrity, "shasum": shasum})
	_, err := h.env.Repos.PutBytes(ctx, rp, data, repo.PutOptions{
		Path:        tarballPath(name, file),
		ContentType: "application/octet-stream",
		Attrs:       attrs,
		CreatedBy:   actor,
		Component:   &repo.ComponentRef{Name: name, Version: version, Attrs: componentAttrs(man)},
		NoOverwrite: !rp.AllowRedeploy(),
	})
	if errors.Is(err, repo.ErrRedeploy) {
		return fmt.Errorf("%w: %s@%s", errVersionExists, name, version)
	}
	return err
}

func (h *Handler) savePackument(ctx context.Context, rp *repo.Repository, name string, pk *packument, actor string) error {
	pk.setStr("_id", name)
	pk.setStr("name", name)
	pk.setStr("_rev", pk.nextRev())
	_, err := h.env.Repos.PutBytes(ctx, rp, pk.bytes(), repo.PutOptions{
		Path:        packumentPath(name),
		ContentType: "application/json",
		CreatedBy:   actor,
	})
	return err
}

func copyTags(t map[string]string) map[string]string {
	out := make(map[string]string, len(t))
	for k, v := range t {
		out[k] = v
	}
	return out
}

// syncTagAttrs records each affected version's dist-tags on its component
// (best effort; used for search and the UI).
func (h *Handler) syncTagAttrs(ctx context.Context, rp *repo.Repository, name string, before, after map[string]string) {
	affected := map[string]bool{}
	for t, v := range before {
		if after[t] != v {
			affected[v] = true
			if after[t] != "" {
				affected[after[t]] = true
			}
		}
	}
	for t, v := range after {
		if before[t] != v {
			affected[v] = true
		}
	}
	for v := range affected {
		if _, err := h.env.Repos.Store.FindComponent(ctx, rp.ID, name, v); err != nil {
			continue
		}
		tags := []string{}
		for t, tv := range after {
			if tv == v {
				tags = append(tags, t)
			}
		}
		sort.Strings(tags)
		if _, err := h.env.Repos.Store.UpsertComponent(ctx, rp.ID, name, v, marshal(map[string]any{"distTags": tags})); err != nil {
			h.env.Logger.Warn("update component dist-tags", "package", name, "version", v, "err", err)
		}
	}
}

// updatePackument handles a packument PUT without attachments: npm
// deprecate, npm unpublish pkg@version (versions removed), dist-tag and
// maintainer changes.
func (h *Handler) updatePackument(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, rev string, req *publishRequest, raw map[string]json.RawMessage) {
	ctx := r.Context()
	unlock := h.lock(rp, name)
	defer unlock()
	pk, _, err := h.hostedPackument(ctx, rp, name)
	if err == nil && len(pk.Versions) == 0 {
		err = repo.ErrNotFound
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if rev != "" && rev != pk.str("_rev") {
		h.fail(w, r, errRevConflict)
		return
	}
	if req.Versions == nil {
		jsonError(w, http.StatusBadRequest, "the package document must include versions")
		return
	}
	var removed []string
	for v := range pk.Versions {
		if _, ok := req.Versions[v]; !ok {
			removed = append(removed, v)
		}
	}
	if len(removed) > 0 && !h.env.Can(r, rp, authz.Delete) {
		jsonError(w, http.StatusForbidden, "removing versions requires delete permission")
		return
	}
	for v, man := range req.Versions {
		cur, ok := pk.Versions[v]
		if !ok {
			jsonError(w, http.StatusBadRequest, "version "+v+" has no tarball; publish it with npm publish")
			return
		}
		if dep, ok := man["deprecated"]; ok && rawStr(man, "deprecated") != "" {
			cur["deprecated"] = dep
		} else {
			delete(cur, "deprecated")
		}
	}
	oldTags := copyTags(pk.DistTags)
	for _, v := range removed {
		file := tarballFile(name, v, pk.Versions[v])
		delete(pk.Versions, v)
		if a, err := h.env.Repos.GetAsset(ctx, rp, tarballPath(name, file)); err == nil {
			if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
				h.fail(w, r, err)
				return
			}
		}
	}
	if _, ok := raw["dist-tags"]; ok {
		pk.DistTags = map[string]string{}
		for t, v := range req.DistTags {
			if tagRe.MatchString(t) {
				pk.DistTags[t] = v
			}
		}
	}
	pk.fixTags()
	if m, ok := raw["maintainers"]; ok {
		pk.Fields["maintainers"] = m
	}
	if len(pk.Versions) == 0 {
		if _, err := h.env.Repos.Store.DeleteAssetsByPrefix(ctx, rp.ID, name+"/"); err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	pk.Time["modified"] = marshal(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	if err := h.savePackument(ctx, rp, name, pk, format.Actor(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	h.syncTagAttrs(ctx, rp, name, oldTags, pk.DistTags)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": name, "rev": pk.str("_rev")})
}

// deletePackage removes a package with all versions (npm unpublish pkg --force).
func (h *Handler) deletePackage(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, rev string) {
	ctx := r.Context()
	unlock := h.lock(rp, name)
	defer unlock()
	if rp.IsHosted() && rev != "" {
		if pk, _, err := h.hostedPackument(ctx, rp, name); err == nil && pk.str("_rev") != rev {
			h.fail(w, r, errRevConflict)
			return
		}
	}
	n, err := h.env.Repos.Store.DeleteAssetsByPrefix(ctx, rp.ID, name+"/")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if n == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) deleteTarball(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, file string) {
	ctx := r.Context()
	a, err := h.env.Repos.GetAsset(ctx, rp, tarballPath(name, file))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// distTags implements /-/package/{package}/dist-tags[/{tag}].
func (h *Handler) distTags(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	name, rest, ok := splitPackage(p)
	if !ok || len(rest) == 0 || rest[0] != "dist-tags" || len(rest) > 2 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	tag := ""
	if len(rest) == 2 {
		tag = rest[1]
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.env.Authorize(w, r, rp, authz.Read) {
			return
		}
		pk, err := h.packument(ctx, rp, name)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if tag != "" {
			v, ok := pk.DistTags[tag]
			if !ok {
				jsonError(w, http.StatusNotFound, "no such dist-tag")
				return
			}
			writeJSON(w, http.StatusOK, v)
			return
		}
		writeJSON(w, http.StatusOK, pk.DistTags)
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		if tag == "" {
			methodNotAllowed(w, "GET")
			return
		}
		if !h.writable(w, r, rp, authz.Write) {
			return
		}
		if !tagRe.MatchString(tag) {
			jsonError(w, http.StatusBadRequest, "invalid dist-tag")
			return
		}
		var version string
		if r.Method != http.MethodDelete {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&version); err != nil {
				jsonError(w, http.StatusBadRequest, `body must be a JSON string such as "1.2.3"`)
				return
			}
		} else if tag == "latest" {
			jsonError(w, http.StatusBadRequest, "the latest dist-tag cannot be removed")
			return
		}
		unlock := h.lock(rp, name)
		defer unlock()
		pk, _, err := h.hostedPackument(ctx, rp, name)
		if err == nil && len(pk.Versions) == 0 {
			err = repo.ErrNotFound
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		oldTags := copyTags(pk.DistTags)
		if r.Method == http.MethodDelete {
			if _, ok := pk.DistTags[tag]; !ok {
				jsonError(w, http.StatusNotFound, "no such dist-tag")
				return
			}
			delete(pk.DistTags, tag)
		} else {
			if _, ok := pk.Versions[version]; !ok {
				jsonError(w, http.StatusNotFound, "version "+version+" not found")
				return
			}
			pk.DistTags[tag] = version
		}
		pk.Time["modified"] = marshal(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
		if err := h.savePackument(ctx, rp, name, pk, format.Actor(r)); err != nil {
			h.fail(w, r, err)
			return
		}
		h.syncTagAttrs(ctx, rp, name, oldTags, pk.DistTags)
		writeJSON(w, http.StatusOK, pk.DistTags)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

// Upload implements the generic upload API: an `npm pack` tarball whose
// package/package.json is published. The optional "tag" field sets the
// dist-tag (default "latest").
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, format.BadRequest("uploads require a hosted repository")
	}
	data, err := io.ReadAll(io.LimitReader(u.File, MaxPublish+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPublish {
		return nil, format.BadRequest("tarball too large")
	}
	manifestJSON, readme, err := readTarball(data)
	if err != nil {
		return nil, format.BadRequest("not an npm package tarball: %v", err)
	}
	var man map[string]json.RawMessage
	if err := json.Unmarshal(manifestJSON, &man); err != nil {
		return nil, format.BadRequest("invalid package.json: %v", err)
	}
	name, version := rawStr(man, "name"), rawStr(man, "version")
	if name == "" || version == "" {
		return nil, format.BadRequest("package.json must have a name and a version")
	}
	if readme != "" {
		man["readme"] = marshal(readme)
	}
	tag := u.Fields["tag"]
	if tag == "" {
		tag = "latest"
	}
	file := unscoped(name) + "-" + version + ".tgz"
	if _, err := h.publish(ctx, rp, publishInput{
		Name:     name,
		Versions: map[string]map[string]json.RawMessage{version: man},
		Files:    map[string][]byte{file: data},
		DistTags: map[string]string{tag: version},
		Actor:    u.Uploader.Name,
	}); err != nil {
		return nil, err
	}
	var out []*store.Asset
	for _, p := range []string{tarballPath(name, file), packumentPath(name)} {
		if a, err := h.env.Repos.GetAsset(ctx, rp, p); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// readTarball returns package.json (and README) from the top-level
// directory of an npm package tarball (normally "package/").
func readTarball(data []byte) (manifest []byte, readme string, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, "", err
	}
	tr := tar.NewReader(gz)
	var fallback []byte
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dir, base := path.Split(strings.TrimPrefix(hdr.Name, "./"))
		if strings.Count(dir, "/") != 1 {
			continue
		}
		switch {
		case base == "package.json":
			b, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return nil, "", err
			}
			if dir == "package/" {
				manifest = b
			} else if fallback == nil {
				fallback = b
			}
		case readme == "" && strings.HasPrefix(strings.ToLower(base), "readme"):
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, "", err
			}
			readme = string(b)
		}
	}
	if manifest == nil {
		manifest = fallback
	}
	if manifest == nil {
		return nil, "", errors.New("package.json not found")
	}
	return manifest, readme, nil
}
