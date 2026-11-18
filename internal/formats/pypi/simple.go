package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
)

const (
	jsonType   = "application/vnd.pypi.simple.v1+json"
	htmlType   = "application/vnd.pypi.simple.v1+html"
	apiVersion = "1.1"
)

// distFile is one file on a project page.
type distFile struct {
	Filename string
	// Path is the repository-relative path the file is served from.
	Path string
	// URL is the upstream location (proxy only).
	URL            string
	Hashes         map[string]string
	RequiresPython string
	// HasMetadata: a PEP 658 .metadata file is available; MetadataHashes
	// may be empty when its digest is unknown.
	HasMetadata    bool
	MetadataHashes map[string]string
	Yanked         bool
	YankedReason   string
	Size           int64 // -1 when unknown
	UploadTime     string
	Version        string
}

type projectPage struct {
	Name     string
	Files    []distFile
	Versions []string
}

// ---- negotiation & rendering ----

// negotiate picks the response type from ?format= or the Accept header.
func negotiate(r *http.Request) string {
	switch f := r.URL.Query().Get("format"); f {
	case jsonType, htmlType, "text/html":
		return f
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return "text/html"
	}
	best, bestQ := "", -1.0
	for _, part := range strings.Split(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		q := 1.0
		if qs, ok := params["q"]; ok {
			if f, err := strconv.ParseFloat(qs, 64); err == nil {
				q = f
			}
		}
		var cand string
		switch mt {
		case jsonType, "application/vnd.pypi.simple.latest+json":
			cand = jsonType
		case htmlType, "application/vnd.pypi.simple.latest+html":
			cand = htmlType
		case "text/html", "*/*", "text/*":
			cand = "text/html"
		}
		if cand != "" && q > 0 && q > bestQ {
			best, bestQ = cand, q
		}
	}
	if best == "" {
		return "text/html"
	}
	return best
}

func fileHref(f distFile) string {
	segs := strings.Split(f.Path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	href := "../../" + strings.Join(segs, "/")
	if sum := f.Hashes["sha256"]; sum != "" {
		href += "#sha256=" + sum
	} else {
		for _, alg := range []string{"sha512", "sha384", "sha224", "sha1", "md5"} {
			if sum := f.Hashes[alg]; sum != "" {
				href += "#" + alg + "=" + sum
				break
			}
		}
	}
	return href
}

func metadataAttr(f distFile) string {
	if sum := f.MetadataHashes["sha256"]; sum != "" {
		return "sha256=" + sum
	}
	return "true"
}

func (h *Handler) renderProject(w http.ResponseWriter, r *http.Request, pg *projectPage) {
	w.Header().Set("Vary", "Accept")
	ct := negotiate(r)
	if ct == jsonType {
		type jsonFile struct {
			Filename         string            `json:"filename"`
			URL              string            `json:"url"`
			Hashes           map[string]string `json:"hashes"`
			RequiresPython   string            `json:"requires-python,omitempty"`
			CoreMetadata     any               `json:"core-metadata,omitempty"`
			DistInfoMetadata any               `json:"dist-info-metadata,omitempty"`
			Yanked           any               `json:"yanked,omitempty"`
			Size             *int64            `json:"size,omitempty"`
			UploadTime       string            `json:"upload-time,omitempty"`
		}
		files := make([]jsonFile, 0, len(pg.Files))
		for _, f := range pg.Files {
			jf := jsonFile{Filename: f.Filename, Hashes: f.Hashes, RequiresPython: f.RequiresPython, UploadTime: f.UploadTime}
			jf.URL, _, _ = strings.Cut(fileHref(f), "#")
			if jf.Hashes == nil {
				jf.Hashes = map[string]string{}
			}
			if f.HasMetadata {
				var md any = true
				if len(f.MetadataHashes) > 0 {
					md = f.MetadataHashes
				}
				jf.CoreMetadata, jf.DistInfoMetadata = md, md
			}
			if f.Yanked {
				if f.YankedReason != "" {
					jf.Yanked = f.YankedReason
				} else {
					jf.Yanked = true
				}
			}
			if f.Size >= 0 {
				size := f.Size
				jf.Size = &size
			}
			files = append(files, jf)
		}
		versions := pg.Versions
		if versions == nil {
			versions = []string{}
		}
		writeJSON(w, map[string]any{
			"meta":     map[string]string{"api-version": apiVersion},
			"name":     pg.Name,
			"files":    files,
			"versions": versions,
		})
		return
	}
	var b strings.Builder
	name := html.EscapeString(pg.Name)
	b.WriteString("<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"" + apiVersion + "\">\n")
	b.WriteString("<title>Links for " + name + "</title>\n</head>\n<body>\n<h1>Links for " + name + "</h1>\n")
	for _, f := range pg.Files {
		b.WriteString(`<a href="` + html.EscapeString(fileHref(f)) + `"`)
		if f.RequiresPython != "" {
			b.WriteString(` data-requires-python="` + html.EscapeString(f.RequiresPython) + `"`)
		}
		if f.HasMetadata {
			md := html.EscapeString(metadataAttr(f))
			b.WriteString(` data-dist-info-metadata="` + md + `" data-core-metadata="` + md + `"`)
		}
		if f.Yanked {
			b.WriteString(` data-yanked="` + html.EscapeString(f.YankedReason) + `"`)
		}
		b.WriteString(">" + html.EscapeString(f.Filename) + "</a><br/>\n")
	}
	b.WriteString("</body>\n</html>\n")
	w.Header().Set("Content-Type", ct+"; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", jsonType)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (h *Handler) projectPage(w http.ResponseWriter, r *http.Request, rp *repo.Repository, project string) {
	pg, err := h.page(r.Context(), rp, project)
	if err == nil && len(pg.Files) == 0 {
		err = repo.ErrNotFound
	}
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.renderProject(w, r, pg)
}

func (h *Handler) rootIndex(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	names, err := h.projectNames(r.Context(), rp)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	w.Header().Set("Vary", "Accept")
	ct := negotiate(r)
	if ct == jsonType {
		projects := make([]map[string]string, 0, len(names))
		for _, n := range names {
			projects = append(projects, map[string]string{"name": n})
		}
		writeJSON(w, map[string]any{"meta": map[string]string{"api-version": apiVersion}, "projects": projects})
		return
	}
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"" + apiVersion + "\">\n<title>Simple index</title>\n</head>\n<body>\n")
	for _, n := range names {
		b.WriteString(`<a href="` + html.EscapeString(url.PathEscape(n)) + `/">` + html.EscapeString(n) + "</a><br/>\n")
	}
	b.WriteString("</body>\n</html>\n")
	w.Header().Set("Content-Type", ct+"; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// ---- page assembly ----

func (h *Handler) page(ctx context.Context, rp *repo.Repository, project string) (*projectPage, error) {
	switch rp.Kind {
	case repo.KindProxy:
		return h.proxyPage(ctx, rp, project, rp.Cfg.Proxy.MetadataTTL())
	case repo.KindGroup:
		merged := &projectPage{Name: project}
		seen := map[string]bool{}
		versions := map[string]bool{}
		found := false
		for _, m := range h.groupMembers(ctx, rp, project) {
			pg, err := h.page(ctx, m, project)
			if err != nil {
				if !isNotFound(err) {
					h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "project", project, "err", err)
				}
				continue
			}
			found = true
			for _, f := range pg.Files {
				if !seen[f.Filename] {
					seen[f.Filename] = true
					merged.Files = append(merged.Files, f)
				}
			}
			for _, v := range pg.Versions {
				if !versions[v] {
					versions[v] = true
					merged.Versions = append(merged.Versions, v)
				}
			}
		}
		if !found {
			return nil, repo.ErrNotFound
		}
		return merged, nil
	default:
		return h.hostedPage(ctx, rp, project)
	}
}

// listAssets returns all assets under prefix.
func (h *Handler) listAssets(ctx context.Context, rp *repo.Repository, prefix string) ([]*store.Asset, error) {
	var out []*store.Asset
	after := ""
	for {
		batch, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, prefix, after, 1000)
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 1000 {
			return out, nil
		}
		after = batch[len(batch)-1].Path
	}
}

// assetAttrs are stored on hosted distribution assets.
type assetAttrs struct {
	Filename           string `json:"filename,omitempty"`
	PackageType        string `json:"packagetype,omitempty"`
	RequiresPython     string `json:"requires_python,omitempty"`
	CoreMetadataSHA256 string `json:"core_metadata_sha256,omitempty"`
	Yanked             string `json:"yanked,omitempty"`
}

func (h *Handler) hostedPage(ctx context.Context, rp *repo.Repository, project string) (*projectPage, error) {
	assets, err := h.listAssets(ctx, rp, "packages/"+project+"/")
	if err != nil {
		return nil, err
	}
	pg := &projectPage{Name: project}
	seenVersion := map[string]bool{}
	for _, a := range assets {
		fp, ok := parseFilePath(a.Path)
		if !ok || fp.Metadata {
			continue
		}
		var attrs assetAttrs
		_ = json.Unmarshal(a.Attrs, &attrs)
		f := distFile{
			Filename:       fp.Filename,
			Path:           a.Path,
			Hashes:         map[string]string{"sha256": storage.Digest(a.Digest).Hex()},
			RequiresPython: attrs.RequiresPython,
			Size:           a.Size,
			UploadTime:     a.CreatedAt.UTC().Format(time.RFC3339),
			Version:        fp.Version,
		}
		if attrs.CoreMetadataSHA256 != "" {
			f.HasMetadata = true
			f.MetadataHashes = map[string]string{"sha256": attrs.CoreMetadataSHA256}
		}
		if attrs.Yanked != "" {
			f.Yanked, f.YankedReason = true, attrs.Yanked
		}
		pg.Files = append(pg.Files, f)
		if !seenVersion[fp.Version] {
			seenVersion[fp.Version] = true
			pg.Versions = append(pg.Versions, fp.Version)
		}
	}
	if len(pg.Files) == 0 {
		return nil, repo.ErrNotFound
	}
	return pg, nil
}

func (h *Handler) projectNames(ctx context.Context, rp *repo.Repository) ([]string, error) {
	switch rp.Kind {
	case repo.KindProxy:
		// The upstream index is huge; list the projects cached so far.
		assets, err := h.listAssets(ctx, rp, "simple/")
		if err != nil {
			return nil, err
		}
		var names []string
		for _, a := range assets {
			n := strings.TrimPrefix(a.Path, "simple/")
			if n != "" && !strings.Contains(n, "/") {
				names = append(names, n)
			}
		}
		return names, nil
	case repo.KindGroup:
		set := map[string]bool{}
		for _, m := range h.env.Members(ctx, rp) {
			ns, err := h.projectNames(ctx, m)
			if err != nil {
				h.env.Logger.Warn("group member index failed", "group", rp.Name, "member", m.Name, "err", err)
				continue
			}
			for _, n := range ns {
				set[n] = true
			}
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		return names, nil
	default:
		return h.env.Repos.Store.ListComponentNames(ctx, rp.ID)
	}
}

// ---- upstream index parsing ----

// parseIndex parses an upstream project page (PEP 691 JSON or PEP 503
// HTML) and resolves file URLs against base.
func parseIndex(body []byte, contentType, base, project string) (*projectPage, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	var pg *projectPage
	mt, _, _ := mime.ParseMediaType(contentType)
	if strings.Contains(mt, "json") || (mt == "" && len(body) > 0 && body[0] == '{') {
		pg, err = parseJSONIndex(body)
	} else {
		pg = parseHTMLIndex(body)
	}
	if err != nil {
		return nil, err
	}
	pg.Name = project
	files := pg.Files[:0]
	derive := len(pg.Versions) == 0
	seenVersion := map[string]bool{}
	for _, f := range pg.Files {
		if !validFilename(f.Filename) {
			continue
		}
		u, err := baseURL.Parse(f.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment = ""
		f.URL = u.String()
		_, version, _, _ := parseFilename(f.Filename, project)
		if !validVersion(version) {
			version = ""
		}
		f.Version = version
		f.Path = filePathFor(project, version, f.Filename)
		files = append(files, f)
		if derive && version != "" && !seenVersion[version] {
			seenVersion[version] = true
			pg.Versions = append(pg.Versions, version)
		}
	}
	pg.Files = files
	return pg, nil
}

func parseJSONIndex(body []byte) (*projectPage, error) {
	var doc struct {
		Files []struct {
			Filename         string            `json:"filename"`
			URL              string            `json:"url"`
			Hashes           map[string]string `json:"hashes"`
			RequiresPython   *string           `json:"requires-python"`
			CoreMetadata     json.RawMessage   `json:"core-metadata"`
			DistInfoMetadata json.RawMessage   `json:"dist-info-metadata"`
			Yanked           json.RawMessage   `json:"yanked"`
			Size             *int64            `json:"size"`
			UploadTime       string            `json:"upload-time"`
		} `json:"files"`
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid upstream JSON index: %w", err)
	}
	pg := &projectPage{Versions: doc.Versions}
	for _, jf := range doc.Files {
		f := distFile{Filename: jf.Filename, URL: jf.URL, Hashes: jf.Hashes, Size: -1, UploadTime: jf.UploadTime}
		if jf.RequiresPython != nil {
			f.RequiresPython = *jf.RequiresPython
		}
		if jf.Size != nil {
			f.Size = *jf.Size
		}
		md := jf.CoreMetadata
		if len(md) == 0 || string(md) == "null" {
			md = jf.DistInfoMetadata
		}
		f.HasMetadata, f.MetadataHashes = parseMetadataField(md)
		if len(jf.Yanked) > 0 {
			var b bool
			var s string
			if json.Unmarshal(jf.Yanked, &b) == nil {
				f.Yanked = b
			} else if json.Unmarshal(jf.Yanked, &s) == nil {
				f.Yanked, f.YankedReason = true, s
			}
		}
		pg.Files = append(pg.Files, f)
	}
	return pg, nil
}

func parseMetadataField(raw json.RawMessage) (bool, map[string]string) {
	if len(raw) == 0 {
		return false, nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) == nil {
		return true, m
	}
	return false, nil
}

var (
	anchorRe = regexp.MustCompile(`(?is)<a\s+([^>]*)>(.*?)</a\s*>`)
	attrRe   = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+)))?`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
)

func parseHTMLIndex(body []byte) *projectPage {
	pg := &projectPage{}
	for _, m := range anchorRe.FindAllSubmatch(body, -1) {
		attrs := map[string]string{}
		for _, am := range attrRe.FindAllSubmatch(m[1], -1) {
			v := string(am[2]) + string(am[3]) + string(am[4])
			attrs[strings.ToLower(string(am[1]))] = html.UnescapeString(v)
		}
		href, ok := attrs["href"]
		if !ok {
			continue
		}
		text := strings.TrimSpace(html.UnescapeString(string(tagRe.ReplaceAll(m[2], nil))))
		f := distFile{Filename: text, Hashes: map[string]string{}, Size: -1, RequiresPython: attrs["data-requires-python"]}
		u, frag, _ := strings.Cut(href, "#")
		f.URL = u
		if alg, sum, ok := strings.Cut(frag, "="); ok && sum != "" {
			f.Hashes[strings.ToLower(alg)] = sum
		}
		if f.Filename == "" {
			if pu, err := url.Parse(u); err == nil {
				f.Filename = pathBase(pu.Path)
			}
		}
		md, ok := attrs["data-core-metadata"]
		if !ok {
			md, ok = attrs["data-dist-info-metadata"]
		}
		if ok {
			f.HasMetadata = md != "false"
			if alg, sum, ok := strings.Cut(md, "="); ok && sum != "" {
				f.MetadataHashes = map[string]string{strings.ToLower(alg): sum}
			}
		}
		if y, ok := attrs["data-yanked"]; ok {
			f.Yanked, f.YankedReason = true, y
		}
		pg.Files = append(pg.Files, f)
	}
	return pg
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
