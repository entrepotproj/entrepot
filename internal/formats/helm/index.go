package helm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
)

const (
	chartsDir = "charts/"
	indexPath = "index.yaml"
	// maxIndex bounds upstream index documents (Bitnami's is tens of MB).
	maxIndex = 512 << 20
	maxDepth = 4
)

// chartVersion is one entry of a repository index.
type chartVersion struct {
	Name, Version string
	// Meta holds the metadata of hosted charts (no urls/created/digest).
	// Proxied entries keep only their rendered form (body) to bound memory
	// with large upstream indexes.
	Meta    map[string]any
	File    string // {name}-{version}.tgz
	Digest  string // sha256 hex of the package, when known
	Created string
	// Upstream is the absolute package URL of a proxied chart.
	Upstream string
	// body is the rendered index entry (a YAML mapping at column 0) with
	// Entrepot URLs.
	body []byte
	// hosted is true for charts stored in a hosted repository.
	hosted bool
	// owner is the (hosted or proxy) repository serving the package.
	owner *repo.Repository
}

// entry returns the index entry with Entrepot URLs as plain values.
func (cv *chartVersion) entry() map[string]any {
	if cv.Meta == nil {
		var n yaml.Node
		if yaml.Unmarshal(cv.entryYAML(), &n) == nil {
			if m, ok := nodeValue(&n).(map[string]any); ok {
				return m
			}
		}
		return map[string]any{"name": cv.Name, "version": cv.Version, "urls": []string{chartsDir + cv.File}}
	}
	m := make(map[string]any, len(cv.Meta)+3)
	for k, v := range cv.Meta {
		m[k] = v
	}
	m["urls"] = []string{chartsDir + cv.File}
	if cv.Created != "" {
		m["created"] = cv.Created
	}
	if cv.Digest != "" {
		m["digest"] = cv.Digest
	} else {
		delete(m, "digest")
	}
	return m
}

// entryYAML returns the rendered entry.
func (cv *chartVersion) entryYAML() []byte {
	if cv.body == nil {
		cv.body = encodeYAML(cv.entry())
	}
	return cv.body
}

func encodeYAML(v any) []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(v)
	_ = enc.Close()
	return buf.Bytes()
}

type chartIndex struct {
	entries map[string][]*chartVersion
	byFile  map[string]*chartVersion
	// fingerprint identifies the content (ETag, render cache key).
	fingerprint string
}

func newIndex() *chartIndex {
	return &chartIndex{entries: map[string][]*chartVersion{}, byFile: map[string]*chartVersion{}}
}

func (ix *chartIndex) add(cv *chartVersion) {
	ix.entries[cv.Name] = append(ix.entries[cv.Name], cv)
	if _, ok := ix.byFile[cv.File]; !ok {
		ix.byFile[cv.File] = cv
	}
}

func (ix *chartIndex) sort() {
	for _, vs := range ix.entries {
		sort.SliceStable(vs, func(i, j int) bool { return compareVersions(vs[i].Version, vs[j].Version) > 0 })
	}
}

func (ix *chartIndex) find(name, version string) *chartVersion {
	for _, cv := range ix.entries[name] {
		if cv.Version == version {
			return cv
		}
	}
	return nil
}

// render serialises the index as index.yaml (entries sorted by name,
// versions newest first).
func (ix *chartIndex) render() []byte {
	names := make([]string, 0, len(ix.entries))
	size := 64
	for name, vs := range ix.entries {
		if len(vs) == 0 {
			continue
		}
		names = append(names, name)
		for _, cv := range vs {
			size += len(cv.entryYAML()) + 64
		}
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.Grow(size)
	b.WriteString("apiVersion: v1\n")
	if len(names) == 0 {
		b.WriteString("entries: {}\n")
	} else {
		b.WriteString("entries:\n")
	}
	for _, name := range names {
		b.WriteString("  ")
		b.Write(bytes.TrimSpace(encodeYAML(name)))
		b.WriteString(":\n")
		for _, cv := range ix.entries[name] {
			body := bytes.TrimRight(cv.entryYAML(), "\n")
			for i, line := range bytes.Split(body, []byte("\n")) {
				if i == 0 {
					b.WriteString("  - ")
				} else if len(line) > 0 {
					b.WriteString("    ")
				}
				b.Write(line)
				b.WriteByte('\n')
			}
		}
	}
	b.WriteString("generated: \"" + time.Now().UTC().Format(time.RFC3339Nano) + "\"\n")
	return b.Bytes()
}

// ---- hosted ----

// assetAttrs are stored on hosted (and cached) chart packages.
type assetAttrs struct {
	Chart       *chartMeta `json:"chart,omitempty"`
	UpstreamURL string     `json:"upstreamUrl,omitempty"`
}

// hostedIndex builds the index of a hosted repository from its stored
// packages.
func (h *Handler) hostedIndex(ctx context.Context, rp *repo.Repository) (*chartIndex, error) {
	ix := newIndex()
	sum := sha256.New()
	after := ""
	for {
		batch, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, chartsDir, after, 1000)
		if err != nil {
			return nil, err
		}
		for _, a := range batch {
			file := strings.TrimPrefix(a.Path, chartsDir)
			if !strings.HasSuffix(file, ".tgz") || strings.Contains(file, "/") {
				continue
			}
			var attrs assetAttrs
			if json.Unmarshal(a.Attrs, &attrs) != nil || attrs.Chart == nil {
				continue
			}
			fmt.Fprintf(sum, "%s %s %d\n", a.Path, a.Digest, a.UpdatedAt.UnixNano())
			ix.add(&chartVersion{
				Name: attrs.Chart.Name, Version: attrs.Chart.Version, Meta: attrs.Chart.metaMap(), File: file,
				Digest: storage.Digest(a.Digest).Hex(), Created: a.CreatedAt.UTC().Format(time.RFC3339Nano),
				hosted: true, owner: rp,
			})
		}
		if len(batch) < 1000 {
			break
		}
		after = batch[len(batch)-1].Path
	}
	ix.sort()
	ix.fingerprint = "h" + hex.EncodeToString(sum.Sum(nil))[:32]
	return ix, nil
}

// ---- proxy ----

func upstreamIndexURL(remote string) string { return proxy.JoinURL(remote, indexPath) }

func (h *Handler) proxyIndexAsset(ctx context.Context, rp *repo.Repository, ttl time.Duration) (*store.Asset, error) {
	return h.env.Proxy.Get(ctx, rp, indexPath, ttl, func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		res, err := h.env.Proxy.FetchURL(ctx, rp, upstreamIndexURL(rp.Cfg.Proxy.RemoteURL), existing, nil)
		if err != nil || res.NotModified {
			return res, err
		}
		res.ContentType = "application/x-yaml"
		return res, nil
	})
}

// proxyIndex returns the parsed upstream index of a proxy repository
// (parsed once per cached document) with blocked charts removed.
func (h *Handler) proxyIndex(ctx context.Context, rp *repo.Repository, ttl time.Duration) (*chartIndex, error) {
	a, err := h.proxyIndexAsset(ctx, rp, ttl)
	if err != nil {
		return nil, err
	}
	key := rp.ID + "\x00" + a.Digest + "\x00" + rp.Cfg.Proxy.RemoteURL
	h.mu.Lock()
	ix, ok := h.parsed[rp.ID]
	h.mu.Unlock()
	if !ok || ix.key != key {
		// Concurrent first requests share one parse.
		v, err, _ := h.sf.Do(key, func() (any, error) {
			parsed, err := h.parseUpstream(ctx, rp, a)
			if err != nil {
				return nil, err
			}
			h.mu.Lock()
			h.parsed[rp.ID] = parsedIndex{key: key, ix: parsed}
			h.mu.Unlock()
			return parsed, nil
		})
		if err != nil {
			return nil, err
		}
		ix = parsedIndex{key: key, ix: v.(*chartIndex)}
	}
	return h.filterRouting(ctx, rp, ix.ix), nil
}

// filterRouting drops charts the repository's routing rule blocks.
func (h *Handler) filterRouting(ctx context.Context, rp *repo.Repository, ix *chartIndex) *chartIndex {
	if h.env.Proxy.Allow == nil || rp.Cfg.Proxy == nil || rp.Cfg.Proxy.RoutingRule == "" {
		return ix
	}
	out := newIndex()
	var blocked []string
	for name, vs := range ix.entries {
		if len(vs) == 0 {
			continue
		}
		if !h.env.Proxy.Allow(ctx, rp, chartsDir+vs[0].File) {
			blocked = append(blocked, name)
			continue
		}
		out.entries[name] = vs
		for _, cv := range vs {
			if _, ok := out.byFile[cv.File]; !ok {
				out.byFile[cv.File] = cv
			}
		}
	}
	if len(blocked) == 0 {
		return ix
	}
	sort.Strings(blocked)
	sum := sha256.Sum256([]byte(ix.fingerprint + "\x00" + strings.Join(blocked, "\x00")))
	out.fingerprint = "r" + hex.EncodeToString(sum[:16])
	return out
}

func (h *Handler) parseUpstream(ctx context.Context, rp *repo.Repository, a *store.Asset) (*chartIndex, error) {
	data, err := h.env.Repos.ReadAll(ctx, rp, a, maxIndex)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimRight(rp.Cfg.Proxy.RemoteURL, "/") + "/")
	if err != nil {
		return nil, err
	}
	ix, err := parseIndexDocument(data, base, rp)
	if err != nil {
		return nil, fmt.Errorf("upstream index.yaml of %s is invalid: %w", rp.Name, err)
	}
	ix.fingerprint = "p" + storage.Digest(a.Digest).Hex()[:32]
	return ix, nil
}

// parseIndexDocument parses an index.yaml. Large indexes (Bitnami's is
// tens of megabytes) would need gigabytes as a single YAML node tree, so
// the usual block layout is split per chart and parsed chunk by chunk; any
// other layout (JSON, flow style) is parsed as a whole.
func parseIndexDocument(data []byte, base *url.URL, owner *repo.Repository) (*chartIndex, error) {
	ix := newIndex()
	add := func(name string, list *yaml.Node) {
		if list.Kind != yaml.SequenceNode || !validName(name) {
			return
		}
		for _, item := range list.Content {
			if cv := upstreamVersion(name, item, base); cv != nil {
				cv.owner = owner
				ix.add(cv)
			}
		}
	}
	if chunks, ok := splitEntries(data); ok {
		for _, c := range chunks {
			var doc yaml.Node
			if err := yaml.Unmarshal(c, &doc); err != nil {
				return nil, err
			}
			m := docRoot(&doc)
			if m == nil || m.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(m.Content); i += 2 {
				add(m.Content[i].Value, m.Content[i+1])
			}
		}
	} else {
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		entries := mapValue(docRoot(&doc), "entries")
		if entries != nil && entries.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(entries.Content); i += 2 {
				add(entries.Content[i].Value, entries.Content[i+1])
			}
		}
	}
	ix.sort()
	return ix, nil
}

func docRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

// splitEntries splits the block-style "entries:" mapping of an index into
// one YAML document per chart (dedented by two columns). ok is false when
// the document does not have the expected layout.
func splitEntries(data []byte) (chunks [][]byte, ok bool) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	start := -1
	for i, l := range lines {
		t := bytes.TrimRight(l, " \r\n")
		if bytes.Equal(t, []byte("entries:")) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}
	var cur []byte
	flush := func() {
		if cur != nil {
			chunks = append(chunks, cur)
			cur = nil
		}
	}
	for _, l := range lines[start:] {
		t := bytes.TrimRight(l, " \r\n")
		if len(t) == 0 || bytes.HasPrefix(bytes.TrimLeft(t, " "), []byte("#")) {
			if cur != nil {
				cur = append(cur, '\n')
			}
			continue
		}
		indent := len(t) - len(bytes.TrimLeft(t, " "))
		switch {
		case indent == 0:
			// End of the entries mapping (e.g. "generated:").
			flush()
			return chunks, true
		case indent < 2 || bytes.HasPrefix(t, []byte("\t")):
			return nil, false
		case indent == 2 && t[2] != '-':
			// A chart name ("  nginx:").
			if !bytes.HasSuffix(t, []byte(":")) {
				return nil, false
			}
			flush()
			cur = append([]byte{}, l[2:]...)
		default:
			if cur == nil {
				return nil, false
			}
			cur = append(cur, l[2:]...)
		}
	}
	flush()
	return chunks, true
}

// upstreamVersion converts an upstream entry: it resolves the package URL
// and renders the entry with its URL rewritten to charts/{file}.
func upstreamVersion(name string, item *yaml.Node, base *url.URL) *chartVersion {
	if item.Kind != yaml.MappingNode {
		return nil
	}
	scalar := func(key string) string {
		if v := mapValue(item, key); v != nil && v.Kind == yaml.ScalarNode {
			return v.Value
		}
		return ""
	}
	version := scalar("version")
	if !validVersion(version) {
		return nil
	}
	if n := scalar("name"); n != "" && n != name {
		return nil
	}
	var target string
	urls := mapValue(item, "urls")
	if urls != nil && urls.Kind == yaml.SequenceNode {
		for _, u := range urls.Content {
			if u.Kind != yaml.ScalarNode || u.Value == "" {
				continue
			}
			ref, err := url.Parse(u.Value)
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref)
			if abs.Scheme == "http" || abs.Scheme == "https" {
				target = abs.String()
				break
			}
		}
	}
	if target == "" {
		return nil
	}
	file := chartFile(name, version)
	cv := &chartVersion{Name: name, Version: version, File: file, Upstream: target, Created: scalar("created")}
	if d := scalar("digest"); len(d) == 64 {
		cv.Digest = strings.ToLower(d)
	}
	*urls = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: chartsDir + file},
	}}
	item.Style = 0
	cv.body = encodeYAML(item)
	return cv
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// nodeValue converts a YAML node to plain values. Scalars keep their
// literal text (so versions such as 1.10 are not turned into floats),
// except booleans and nulls.
func nodeValue(n *yaml.Node) any {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return nodeValue(n.Content[0])
		}
		return nil
	case yaml.AliasNode:
		if n.Alias != nil {
			return nodeValue(n.Alias)
		}
		return nil
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeValue(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			s = append(s, nodeValue(c))
		}
		return s
	default:
		switch n.ShortTag() {
		case "!!bool":
			var b bool
			if n.Decode(&b) == nil {
				return b
			}
		case "!!null":
			return nil
		}
		return n.Value
	}
}

// ---- group ----

// groupIndex merges the member indexes: the first member wins for a chart
// version; with preferHosted, chart names present in a hosted member are
// never taken from proxy members.
func (h *Handler) groupIndex(ctx context.Context, rp *repo.Repository, depth int) (*chartIndex, error) {
	if depth >= maxDepth {
		return newIndex(), nil
	}
	var parts []*chartIndex
	for _, m := range h.env.Members(ctx, rp) {
		ix, err := h.index(ctx, m, depth+1)
		if err != nil {
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member index unavailable", "group", rp.Name, "member", m.Name, "err", err)
			}
			continue
		}
		parts = append(parts, ix)
	}
	prefer := rp.Cfg.Group.PrefersHosted()
	hostedNames := map[string]bool{}
	if prefer {
		for _, ix := range parts {
			for name, vs := range ix.entries {
				for _, cv := range vs {
					if cv.hosted {
						hostedNames[name] = true
						break
					}
				}
			}
		}
	}
	out := newIndex()
	sum := sha256.New()
	fmt.Fprintf(sum, "g %v\n", prefer)
	seen := map[string]bool{}
	for _, ix := range parts {
		sum.Write([]byte(ix.fingerprint + "\n"))
		for name, vs := range ix.entries {
			for _, cv := range vs {
				if prefer && hostedNames[name] && !cv.hosted {
					continue
				}
				k := name + "\x00" + cv.Version
				if seen[k] {
					continue
				}
				seen[k] = true
				out.add(cv)
			}
		}
	}
	out.sort()
	out.fingerprint = "g" + hex.EncodeToString(sum.Sum(nil))[:32]
	return out, nil
}

// index returns the index of any repository kind.
func (h *Handler) index(ctx context.Context, rp *repo.Repository, depth int) (*chartIndex, error) {
	switch rp.Kind {
	case repo.KindProxy:
		return h.proxyIndex(ctx, rp, rp.Cfg.Proxy.MetadataTTL())
	case repo.KindGroup:
		return h.groupIndex(ctx, rp, depth)
	default:
		return h.hostedIndex(ctx, rp)
	}
}

// renderedIndex returns index.yaml for rp (cached per content fingerprint).
func (h *Handler) renderedIndex(ctx context.Context, rp *repo.Repository) ([]byte, string, error) {
	ix, err := h.index(ctx, rp, 0)
	if err != nil {
		return nil, "", err
	}
	h.mu.Lock()
	c, ok := h.rendered[rp.ID]
	h.mu.Unlock()
	if ok && c.fingerprint == ix.fingerprint {
		return c.body, c.fingerprint, nil
	}
	body := ix.render()
	h.mu.Lock()
	h.rendered[rp.ID] = renderedIndex{fingerprint: ix.fingerprint, body: body}
	h.mu.Unlock()
	return body, ix.fingerprint, nil
}
