// Package config loads Entrepot configuration from a YAML file with
// ENTREPOT_* environment variable overrides.
//
// Every field can be overridden from the environment. The variable name is
// ENTREPOT_ followed by the upper-cased yaml path joined with underscores, e.g.
// database.url -> ENTREPOT_DATABASE_URL, auth.oidc.clientSecret ->
// ENTREPOT_AUTH_OIDC_CLIENTSECRET. Slices are comma separated.
package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const EnvPrefix = "ENTREPOT"

type Config struct {
	Server   Server   `yaml:"server"`
	Database Database `yaml:"database"`
	Auth     Auth     `yaml:"auth"`
	Storage  Storage  `yaml:"storage"`
	Proxy    Proxy    `yaml:"proxy"`
	Log      Log      `yaml:"log"`
	Secrets  Secrets  `yaml:"secrets"`
	Scan     Scan     `yaml:"scan"`
	Cleanup  Cleanup  `yaml:"cleanup"`
	Usage    Usage    `yaml:"usage"`
	// BlobStores are created (or updated) at startup. Useful for declaring the
	// volumes mounted by the Helm chart. Stores can also be managed via the API.
	BlobStores []BlobStoreSpec `yaml:"blobStores"`
}

type Server struct {
	Addr string `yaml:"addr"`
	// BaseURL is the externally visible URL (e.g. https://entrepot.example.com).
	// Used for OIDC redirects, Docker token realms and rewriting proxied
	// metadata. When empty it is derived from each request.
	BaseURL         string        `yaml:"baseURL"`
	ReadTimeout     time.Duration `yaml:"readTimeout"`
	ShutdownTimeout time.Duration `yaml:"shutdownTimeout"`
	// TrustForwardedHeaders honours X-Forwarded-Proto/Host when deriving URLs.
	TrustForwardedHeaders bool `yaml:"trustForwardedHeaders"`
}

type Database struct {
	URL      string `yaml:"url"`
	MaxConns int32  `yaml:"maxConns"`
	// AutoMigrate runs schema migrations on startup.
	AutoMigrate bool `yaml:"autoMigrate"`
}

type Auth struct {
	// SessionSecret encrypts UI session cookies and signs registry tokens.
	// Must be at least 32 bytes and shared by all replicas.
	SessionSecret string `yaml:"sessionSecret"`
	// SessionTTL is the lifetime of a UI login session.
	SessionTTL time.Duration `yaml:"sessionTTL"`
	// AdminGroups: members of these OIDC groups are global administrators.
	AdminGroups []string `yaml:"adminGroups"`
	// AdminUsers: these usernames are global administrators.
	AdminUsers []string `yaml:"adminUsers"`
	// BootstrapToken is a break-glass admin bearer token (from a K8s Secret).
	BootstrapToken string `yaml:"bootstrapToken"`
	// AnonymousAccess allows unauthenticated users to read repositories that
	// have anonymousRead enabled. When false anonymous access is always denied.
	AnonymousAccess bool         `yaml:"anonymousAccess"`
	OIDC            OIDC         `yaml:"oidc"`
	GitLab          []GitLabSpec `yaml:"gitlab"`
}

type OIDC struct {
	Enabled      bool     `yaml:"enabled"`
	IssuerURL    string   `yaml:"issuerURL"`
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
	// GroupsClaim is the claim holding group membership (Keycloak: "groups").
	GroupsClaim string `yaml:"groupsClaim"`
	// UsernameClaim is the claim used as username (default preferred_username).
	UsernameClaim string `yaml:"usernameClaim"`
	// GivenNameClaim is the claim holding the user's first name, shown in the
	// dashboard greeting (default given_name). When the claim is absent the
	// dashboard shows the username instead.
	GivenNameClaim string `yaml:"givenNameClaim"`
	// BearerAudiences are accepted "aud" values for access tokens presented
	// directly as bearer tokens. Defaults to ClientID.
	BearerAudiences []string `yaml:"bearerAudiences"`
	// DisplayName shown on the login button.
	DisplayName string `yaml:"displayName"`
}

// GitLabSpec trusts CI/CD id_tokens issued by a GitLab instance.
type GitLabSpec struct {
	// Name identifies this GitLab instance in trust policies.
	Name      string `yaml:"name"`
	IssuerURL string `yaml:"issuerURL"`
	// Audience the id_token must carry (the `aud:` in .gitlab-ci.yml).
	// Defaults to server.baseURL.
	Audience string `yaml:"audience"`
	// API enables feedback (commit statuses, MR notes) for scans of
	// artifacts published by CI jobs of this instance.
	API GitLabAPI `yaml:"api"`
}

// GitLabAPI configures calls to the GitLab REST API.
type GitLabAPI struct {
	// URL of the GitLab instance (defaults to issuerURL).
	URL string `yaml:"url"`
	// Token is a GitLab access token with the "api" scope. Prefer TokenEnv or
	// TokenFile so the token is not stored in the config file.
	Token     string `yaml:"token"`
	TokenEnv  string `yaml:"tokenEnv"`
	TokenFile string `yaml:"tokenFile"`
}

// Secrets configures encryption of secrets stored in the database.
type Secrets struct {
	// Key encrypts secrets at rest (>= 32 bytes). Defaults to a key derived
	// from auth.sessionSecret. Must be identical on all replicas.
	Key string `yaml:"key"`
	// PreviousKeys can still decrypt values during a key rotation.
	PreviousKeys []string `yaml:"previousKeys"`
}

// Scan configures the scanning pipeline.
type Scan struct {
	// Workers is the number of in-process scan workers (0 disables them, e.g.
	// when a separate `entrepot scan-worker` deployment runs the scanners).
	Workers int `yaml:"workers"`
	// WorkDir holds temporary scan inputs (SBOMs, OCI layouts).
	WorkDir string `yaml:"workDir"`
	// JobTimeout bounds a single scan (and webhook callbacks).
	JobTimeout time.Duration `yaml:"jobTimeout"`
	// PollInterval is how often idle workers look for jobs.
	PollInterval time.Duration `yaml:"pollInterval"`
	// ErrorRetryInterval is how long after a failed scan the component is
	// scanned again, in repositories with blockOnError (0 disables).
	ErrorRetryInterval time.Duration `yaml:"errorRetryInterval"`
	// MaxHolds bounds the downloads held waiting for a scan verdict, per
	// process (default 1000); further ones are asked to retry (503).
	MaxHolds int `yaml:"maxHolds"`
}

// Cleanup configures scheduled cleanup policy runs.
type Cleanup struct {
	// Interval between automatic cleanup runs (0 disables the schedule).
	Interval time.Duration `yaml:"interval"`
}

// SecretsKey returns the key material for secrets at rest.
func (c *Config) SecretsKey() string {
	if c.Secrets.Key != "" {
		return c.Secrets.Key
	}
	return "entrepot-secrets:" + c.Auth.SessionSecret
}

// Token resolves the GitLab API token from Token, TokenEnv or TokenFile.
func (g GitLabAPI) ResolveToken() (string, error) {
	switch {
	case g.Token != "":
		return g.Token, nil
	case g.TokenEnv != "":
		return os.Getenv(g.TokenEnv), nil
	case g.TokenFile != "":
		b, err := os.ReadFile(g.TokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

type Storage struct {
	// AllowedRoots restricts the paths filesystem blob stores may use.
	AllowedRoots []string `yaml:"allowedRoots"`
	// TempDir is used for spooling uploads before they are content-addressed.
	TempDir string `yaml:"tempDir"`
}

// Usage configures usage statistics and the activity log.
type Usage struct {
	// RecordDownloads adds every artifact download to the activity log
	// (uploads and deletes are always recorded). Download counters and
	// charts are kept regardless.
	RecordDownloads bool `yaml:"recordDownloads"`
	// ActivityRetention is how long activity events are kept.
	ActivityRetention time.Duration `yaml:"activityRetention"`
	// FlushInterval is how often buffered statistics are written.
	FlushInterval time.Duration `yaml:"flushInterval"`
}

type Proxy struct {
	// Timeout for upstream requests.
	Timeout time.Duration `yaml:"timeout"`
	// UserAgent sent to upstreams.
	UserAgent string `yaml:"userAgent"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"` // json | text
}

type BlobStoreSpec struct {
	Name string            `yaml:"name" json:"name"`
	Type string            `yaml:"type" json:"type"`
	Path string            `yaml:"path" json:"path,omitempty"`
	S3   map[string]string `yaml:"s3" json:"s3,omitempty"`
}

func Default() *Config {
	return &Config{
		Server: Server{
			Addr:            ":8080",
			ReadTimeout:     0,
			ShutdownTimeout: 30 * time.Second,
		},
		Database: Database{
			URL:         "postgres://entrepot:entrepot@localhost:5432/entrepot?sslmode=disable",
			MaxConns:    20,
			AutoMigrate: true,
		},
		Auth: Auth{
			SessionTTL:      12 * time.Hour,
			AnonymousAccess: true,
			OIDC: OIDC{
				Scopes:         []string{"openid", "profile", "email"},
				GroupsClaim:    "groups",
				UsernameClaim:  "preferred_username",
				GivenNameClaim: "given_name",
				DisplayName:    "Single sign-on",
			},
		},
		Storage: Storage{
			AllowedRoots: []string{"/data"},
			TempDir:      os.TempDir(),
		},
		Proxy: Proxy{
			Timeout:   60 * time.Second,
			UserAgent: "entrepot/1.0",
		},
		Log: Log{Level: "info", Format: "json"},
		Scan: Scan{
			Workers:            2,
			WorkDir:            os.TempDir(),
			JobTimeout:         15 * time.Minute,
			PollInterval:       2 * time.Second,
			ErrorRetryInterval: 15 * time.Minute,
			MaxHolds:           1000,
		},
		Cleanup: Cleanup{Interval: 24 * time.Hour},
		Usage:   Usage{RecordDownloads: true, ActivityRetention: 30 * 24 * time.Hour, FlushInterval: 10 * time.Second},
	}
}

// Load reads path (if non-empty) then applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := applyEnv(reflect.ValueOf(cfg).Elem(), EnvPrefix, os.LookupEnv); err != nil {
		return nil, err
	}
	// Secrets may also be supplied as files (K8s secret mounts).
	for env, dst := range map[string]*string{
		"ENTREPOT_AUTH_SESSIONSECRET_FILE":     &cfg.Auth.SessionSecret,
		"ENTREPOT_AUTH_BOOTSTRAPTOKEN_FILE":    &cfg.Auth.BootstrapToken,
		"ENTREPOT_AUTH_OIDC_CLIENTSECRET_FILE": &cfg.Auth.OIDC.ClientSecret,
		"ENTREPOT_DATABASE_URL_FILE":           &cfg.Database.URL,
		"ENTREPOT_SECRETS_KEY_FILE":            &cfg.Secrets.Key,
	} {
		if p := os.Getenv(env); p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", env, err)
			}
			*dst = strings.TrimSpace(string(b))
		}
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	var errs []error
	if c.Database.URL == "" {
		errs = append(errs, errors.New("database.url is required"))
	}
	if c.Auth.SessionSecret == "" {
		errs = append(errs, errors.New("auth.sessionSecret is required (>=32 bytes)"))
	} else if len(c.Auth.SessionSecret) < 32 {
		errs = append(errs, errors.New("auth.sessionSecret must be at least 32 bytes"))
	}
	if c.Auth.OIDC.Enabled {
		if c.Auth.OIDC.IssuerURL == "" || c.Auth.OIDC.ClientID == "" {
			errs = append(errs, errors.New("auth.oidc.issuerURL and auth.oidc.clientID are required when OIDC is enabled"))
		}
	}
	for i, g := range c.Auth.GitLab {
		if g.Name == "" || g.IssuerURL == "" {
			errs = append(errs, fmt.Errorf("auth.gitlab[%d]: name and issuerURL are required", i))
		}
		if g.Audience == "" && c.Server.BaseURL == "" {
			errs = append(errs, fmt.Errorf("auth.gitlab[%d]: audience is required when server.baseURL is unset", i))
		}
	}
	if c.Secrets.Key != "" && len(c.Secrets.Key) < 32 {
		errs = append(errs, errors.New("secrets.key must be at least 32 bytes"))
	}
	c.Server.BaseURL = strings.TrimRight(c.Server.BaseURL, "/")
	return errors.Join(errs...)
}

// GitLabAudience returns the expected aud for a GitLab spec.
func (c *Config) GitLabAudience(g GitLabSpec) string {
	if g.Audience != "" {
		return g.Audience
	}
	return c.Server.BaseURL
}

type lookupFunc func(string) (string, bool)

func applyEnv(v reflect.Value, prefix string, lookup lookupFunc) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + "_" + strings.ToUpper(tag)
		fv := v.Field(i)
		if f.Type.Kind() == reflect.Struct {
			if err := applyEnv(fv, name, lookup); err != nil {
				return err
			}
			continue
		}
		raw, ok := lookup(name)
		if !ok {
			continue
		}
		if err := setValue(fv, raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func setValue(fv reflect.Value, raw string) error {
	if fv.Type() == reflect.TypeOf(time.Duration(0)) {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(d))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			var parts []string
			for _, p := range strings.Split(raw, ",") {
				if p = strings.TrimSpace(p); p != "" {
					parts = append(parts, p)
				}
			}
			fv.Set(reflect.ValueOf(parts))
			return nil
		}
		// Complex slices (gitlab, blobStores) accept YAML/JSON.
		ptr := reflect.New(fv.Type())
		if err := yaml.Unmarshal([]byte(raw), ptr.Interface()); err != nil {
			return err
		}
		fv.Set(ptr.Elem())
	default:
		return fmt.Errorf("unsupported kind %s", fv.Kind())
	}
	return nil
}

func reflectValue(c *Config) reflect.Value { return reflect.ValueOf(c).Elem() }
