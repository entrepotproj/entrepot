package scan

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/entrepotproj/entrepot/internal/secrets"
	"github.com/entrepotproj/entrepot/internal/store"
)

// Scanner types.
const (
	TypeTrivy   = "trivy"
	TypeGrype   = "grype"
	TypeWebhook = "webhook"
	// TypeMetaDefender scans file content with OPSWAT MetaDefender Core.
	TypeMetaDefender = "metadefender"
)

// ScannerConfig is the typed form of scanners.config. Secret fields
// (trivy.serverToken, webhook.secret, metadefender.apiKey) are sealed when
// stored.
type ScannerConfig struct {
	RescanIntervalHours int                   `json:"rescanIntervalHours,omitempty"`
	Trivy               *TrivySettings        `json:"trivy,omitempty"`
	Grype               *GrypeSettings        `json:"grype,omitempty"`
	Webhook             *WebhookSettings      `json:"webhook,omitempty"`
	MetaDefender        *MetaDefenderSettings `json:"metadefender,omitempty"`
}

type TrivySettings struct {
	Binary         string   `json:"binary,omitempty"`
	ServerURL      string   `json:"serverUrl,omitempty"`
	ServerToken    string   `json:"serverToken,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	ExtraArgs      []string `json:"extraArgs,omitempty"`
}

type GrypeSettings struct {
	Binary         string   `json:"binary,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	ExtraArgs      []string `json:"extraArgs,omitempty"`
}

type WebhookSettings struct {
	URL            string `json:"url"`
	Secret         string `json:"secret,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

// MetaDefenderSettings configures a MetaDefender Core scanner.
type MetaDefenderSettings struct {
	// URL of the MetaDefender Core REST API, e.g. https://metadefender:8008.
	URL string `json:"url"`
	// APIKey is sent in the apikey header (sealed at rest).
	APIKey string `json:"apiKey,omitempty"`
	// Rule (workflow) files are processed with; empty for the server default.
	Rule string `json:"rule,omitempty"`
	// TimeoutSeconds bounds the scan of one component (all its files).
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// Concurrency is the number of files of a component analysed at once.
	Concurrency int `json:"concurrency,omitempty"`
	// HashLookup reuses earlier analyses of the same content (default true).
	HashLookup *bool `json:"hashLookup,omitempty"`
	// MaxResultAgeHours is the age after which an earlier analysis found by
	// hash is not reused.
	MaxResultAgeHours int `json:"maxResultAgeHours,omitempty"`
	// WebURL links findings to the result in the MetaDefender web console;
	// {dataId} is replaced, e.g. https://metadefender:8008/#/public/process/dataId/{dataId}.
	WebURL string `json:"webUrl,omitempty"`
	// CACertificate is a PEM bundle trusted for the URL (internal CAs).
	CACertificate string `json:"caCertificate,omitempty"`
}

// MetaDefender defaults and limits.
const (
	DefaultMetaDefenderTimeout     = 600 * time.Second
	DefaultMetaDefenderConcurrency = 4
	MaxMetaDefenderConcurrency     = 32
	DefaultMetaDefenderResultAge   = 24
)

// Timeout is the time allowed for one component.
func (m *MetaDefenderSettings) Timeout() time.Duration {
	if m == nil || m.TimeoutSeconds <= 0 {
		return DefaultMetaDefenderTimeout
	}
	return time.Duration(m.TimeoutSeconds) * time.Second
}

// Parallel is the number of files analysed at once.
func (m *MetaDefenderSettings) Parallel() int {
	switch {
	case m == nil || m.Concurrency <= 0:
		return DefaultMetaDefenderConcurrency
	case m.Concurrency > MaxMetaDefenderConcurrency:
		return MaxMetaDefenderConcurrency
	}
	return m.Concurrency
}

// LookupHashes reports whether earlier analyses are reused.
func (m *MetaDefenderSettings) LookupHashes() bool {
	return m == nil || m.HashLookup == nil || *m.HashLookup
}

// ResultAge is the maximum age of a reused analysis.
func (m *MetaDefenderSettings) ResultAge() time.Duration {
	if m == nil || m.MaxResultAgeHours <= 0 {
		return DefaultMetaDefenderResultAge * time.Hour
	}
	return time.Duration(m.MaxResultAgeHours) * time.Hour
}

// DefaultWebhookTimeout is the time a webhook scanner has to call back.
const DefaultWebhookTimeout = 900 * time.Second

// CallbackTimeout is the time allowed for a webhook callback.
func (w *WebhookSettings) CallbackTimeout() time.Duration {
	if w == nil || w.TimeoutSeconds <= 0 {
		return DefaultWebhookTimeout
	}
	return time.Duration(w.TimeoutSeconds) * time.Second
}

// ParseScannerConfig decodes a stored scanner configuration.
func ParseScannerConfig(raw json.RawMessage) (*ScannerConfig, error) {
	c := &ScannerConfig{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("invalid scanner config: %w", err)
		}
	}
	return c, nil
}

// Seal encrypts the secret fields in place.
func (c *ScannerConfig) Seal(box *secrets.Box) error {
	var err error
	if c.Trivy != nil && c.Trivy.ServerToken != "" && !secrets.IsSealed(c.Trivy.ServerToken) {
		if c.Trivy.ServerToken, err = box.Seal(c.Trivy.ServerToken); err != nil {
			return err
		}
	}
	if c.Webhook != nil && c.Webhook.Secret != "" && !secrets.IsSealed(c.Webhook.Secret) {
		if c.Webhook.Secret, err = box.Seal(c.Webhook.Secret); err != nil {
			return err
		}
	}
	if c.MetaDefender != nil && c.MetaDefender.APIKey != "" && !secrets.IsSealed(c.MetaDefender.APIKey) {
		if c.MetaDefender.APIKey, err = box.Seal(c.MetaDefender.APIKey); err != nil {
			return err
		}
	}
	return nil
}

// Open decrypts the secret fields in place.
func (c *ScannerConfig) Open(box *secrets.Box) error {
	var err error
	if c.Trivy != nil && c.Trivy.ServerToken != "" && box != nil {
		if c.Trivy.ServerToken, err = box.Open(c.Trivy.ServerToken); err != nil {
			return fmt.Errorf("trivy.serverToken: %w", err)
		}
	}
	if c.Webhook != nil && c.Webhook.Secret != "" && box != nil {
		if c.Webhook.Secret, err = box.Open(c.Webhook.Secret); err != nil {
			return fmt.Errorf("webhook.secret: %w", err)
		}
	}
	if c.MetaDefender != nil && c.MetaDefender.APIKey != "" && box != nil {
		if c.MetaDefender.APIKey, err = box.Open(c.MetaDefender.APIKey); err != nil {
			return fmt.Errorf("metadefender.apiKey: %w", err)
		}
	}
	return nil
}

// Reseal re-encrypts secret fields that are still plaintext or sealed with
// a previous key, and reports whether anything changed.
func (c *ScannerConfig) Reseal(box *secrets.Box) (bool, error) {
	changed := false
	for _, f := range c.secretFields() {
		if !box.NeedsReseal(*f) {
			continue
		}
		v, err := box.Reseal(*f)
		if err != nil {
			return changed, err
		}
		*f, changed = v, true
	}
	return changed, nil
}

// secretFields points at every secret value of the configuration.
func (c *ScannerConfig) secretFields() []*string {
	var out []*string
	if c.Trivy != nil && c.Trivy.ServerToken != "" {
		out = append(out, &c.Trivy.ServerToken)
	}
	if c.Webhook != nil && c.Webhook.Secret != "" {
		out = append(out, &c.Webhook.Secret)
	}
	if c.MetaDefender != nil && c.MetaDefender.APIKey != "" {
		out = append(out, &c.MetaDefender.APIKey)
	}
	return out
}

// Redacted returns a copy without secret values.
func (c *ScannerConfig) Redacted() *ScannerConfig {
	out := *c
	if c.Trivy != nil {
		t := *c.Trivy
		t.ServerToken = ""
		out.Trivy = &t
	}
	if c.Webhook != nil {
		w := *c.Webhook
		w.Secret = ""
		out.Webhook = &w
	}
	if c.MetaDefender != nil {
		m := *c.MetaDefender
		m.APIKey = ""
		out.MetaDefender = &m
	}
	return &out
}

// loadedScanner is a scanner with its config parsed and secrets opened.
type loadedScanner struct {
	*store.Scanner
	Cfg *ScannerConfig
}

func (s *Service) loadScanner(sc *store.Scanner) (*loadedScanner, error) {
	cfg, err := ParseScannerConfig(sc.Config)
	if err != nil {
		return nil, err
	}
	if err := cfg.Open(s.Secrets); err != nil {
		return nil, fmt.Errorf("scanner %s: %w", sc.Name, err)
	}
	return &loadedScanner{Scanner: sc, Cfg: cfg}, nil
}
