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
)

// ScannerConfig is the typed form of scanners.config. Secret fields
// (trivy.serverToken, webhook.secret) are sealed when stored.
type ScannerConfig struct {
	RescanIntervalHours int              `json:"rescanIntervalHours,omitempty"`
	Trivy               *TrivySettings   `json:"trivy,omitempty"`
	Grype               *GrypeSettings   `json:"grype,omitempty"`
	Webhook             *WebhookSettings `json:"webhook,omitempty"`
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
	return nil
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
