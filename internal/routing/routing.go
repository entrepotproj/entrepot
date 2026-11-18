// Package routing evaluates routing rules that restrict what proxy
// repositories fetch from their upstream (dependency-confusion protection).
//
// A rule has a mode and a list of regular expressions ("matchers"). The
// regexes are matched against the request's subject, which depends on the
// repository format:
//
//	npm     the package name ("@acme/widgets", "left-pad")
//	pypi    the normalised project name ("acme-utils")
//	docker  the upstream image name ("library/alpine", "acme/api")
//	helm    the chart name ("nginx" for charts/nginx-1.2.3.tgz); index.yaml
//	        is always fetched and the Helm format filters blocked charts out
//	        of it
//	other   the repository path
//
// Mode block: matching subjects are never fetched upstream. Mode allow:
// only matching subjects are fetched upstream. Blocked requests are
// reported to clients as not found. Content already cached and still fresh
// keeps being served.
package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

const (
	ModeAllow = "allow"
	ModeBlock = "block"
)

// Rule is a compiled routing rule.
type Rule struct {
	Name     string
	Mode     string
	Matchers []string
	res      []*regexp.Regexp
}

// Compile validates and compiles a rule.
func Compile(name, mode string, matchers []string) (*Rule, error) {
	if mode != ModeAllow && mode != ModeBlock {
		return nil, fmt.Errorf("mode must be allow or block")
	}
	if len(matchers) == 0 {
		return nil, errors.New("at least one matcher is required")
	}
	r := &Rule{Name: name, Mode: mode, Matchers: matchers}
	for _, m := range matchers {
		if strings.TrimSpace(m) == "" {
			return nil, errors.New("matchers must not be empty")
		}
		re, err := regexp.Compile(m)
		if err != nil {
			return nil, fmt.Errorf("invalid matcher %q: %v", m, err)
		}
		r.res = append(r.res, re)
	}
	return r, nil
}

// Evaluate reports whether subject may be fetched upstream and the matcher
// that matched (empty when none did).
func (r *Rule) Evaluate(subject string) (allowed bool, matched string) {
	for i, re := range r.res {
		if re.MatchString(subject) {
			return r.Mode == ModeAllow, r.Matchers[i]
		}
	}
	return r.Mode == ModeBlock, ""
}

// Service loads rules (briefly cached) and answers proxy Allow checks.
type Service struct {
	Store  *store.Store
	Logger *slog.Logger

	mu    sync.Mutex
	cache map[string]cached
	ttl   time.Duration
}

type cached struct {
	rule    *Rule
	err     error
	expires time.Time
}

func New(st *store.Store) *Service {
	return &Service{Store: st, cache: map[string]cached{}, ttl: 5 * time.Second}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Rule returns the compiled rule (cached for a few seconds).
func (s *Service) Rule(ctx context.Context, name string) (*Rule, error) {
	s.mu.Lock()
	c, ok := s.cache[name]
	s.mu.Unlock()
	if ok && time.Now().Before(c.expires) {
		return c.rule, c.err
	}
	sr, err := s.Store.GetRoutingRule(ctx, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// Database errors are not cached.
		return nil, err
	}
	var rule *Rule
	if err == nil {
		rule, err = Compile(sr.Name, sr.Mode, sr.Matchers)
	}
	s.mu.Lock()
	s.cache[name] = cached{rule: rule, err: err, expires: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return rule, err
}

// Invalidate drops a cached rule (call after updates).
func (s *Service) Invalidate(name string) {
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
}

// Allowed reports whether rp may fetch path from its upstream. path is the
// cache path a format passes to proxy.Cache.Get (request paths work too).
// When the configured rule cannot be loaded the request is denied.
func (s *Service) Allowed(ctx context.Context, rp *repo.Repository, path string) bool {
	if rp == nil || rp.Cfg.Proxy == nil || rp.Cfg.Proxy.RoutingRule == "" {
		return true
	}
	subject, ok := Subject(rp.Format, path)
	if !ok {
		return true
	}
	rule, err := s.Rule(ctx, rp.Cfg.Proxy.RoutingRule)
	if err != nil {
		s.logger().Warn("routing rule unavailable; denying upstream request",
			"repository", rp.Name, "rule", rp.Cfg.Proxy.RoutingRule, "err", err)
		return false
	}
	allowed, matched := rule.Evaluate(subject)
	if !allowed {
		s.logger().Debug("routing rule blocked upstream request", "repository", rp.Name, "rule", rule.Name,
			"subject", subject, "matched", matched)
	}
	return allowed
}

// Subject maps a repository path to the string routing rules are matched
// against. ok is false for paths that are never subject to routing (e.g.
// the Helm repository index, whose entries are filtered individually).
func Subject(format, p string) (subject string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	switch format {
	case "npm":
		return npmSubject(p), true
	case "pypi":
		return pypiSubject(p), true
	case "docker":
		return dockerSubject(p), true
	case "helm":
		if p == "index.yaml" || p == "index.yml" {
			return "", false
		}
		return helmSubject(p), true
	default:
		return p, true
	}
}

func npmSubject(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	if strings.HasPrefix(p, "-/") || p == "-" {
		return p
	}
	if i := strings.Index(p, "/-/"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	if strings.HasPrefix(segs[0], "@") && len(segs) > 1 {
		return segs[0] + "/" + segs[1]
	}
	return segs[0]
}

func pypiSubject(p string) string {
	segs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	if len(segs) >= 2 && (segs[0] == "simple" || segs[0] == "packages") && segs[1] != "" {
		return normalizePyPI(segs[1])
	}
	return p
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

func normalizePyPI(name string) string { return strings.ToLower(pypiSep.ReplaceAllString(name, "-")) }

func dockerSubject(p string) string {
	for _, marker := range []string{"/_manifests/", "/_tags/", "/_blobs/", "/manifests/", "/blobs/", "/tags/"} {
		if i := strings.Index(p, marker); i >= 0 {
			return p[:i]
		}
	}
	return p
}

var helmFile = regexp.MustCompile(`^(.+)-v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\.tgz(\.prov)?$`)

func helmSubject(p string) string {
	f := pathBase(p)
	if m := helmFile.FindStringSubmatch(f); m != nil {
		return m[1]
	}
	return f
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
