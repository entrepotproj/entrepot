package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnvOverrides(t *testing.T) {
	env := map[string]string{
		"ENTREPOT_DATABASE_URL":        "postgres://env",
		"ENTREPOT_AUTH_SESSIONSECRET":  "0123456789abcdef0123456789abcdef",
		"ENTREPOT_AUTH_OIDC_ENABLED":   "true",
		"ENTREPOT_AUTH_OIDC_ISSUERURL": "https://idp",
		"ENTREPOT_AUTH_OIDC_CLIENTID":  "c",
		"ENTREPOT_AUTH_ADMINGROUPS":    "a, b",
		"ENTREPOT_AUTH_SESSIONTTL":     "2h",
		"ENTREPOT_DATABASE_MAXCONNS":   "7",
		"ENTREPOT_AUTH_GITLAB":         `[{"name":"gl","issuerURL":"https://gitlab","audience":"x"}]`,
	}
	cfg := Default()
	if err := applyEnv(reflectValue(cfg), EnvPrefix, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	if cfg.Database.URL != "postgres://env" || !cfg.Auth.OIDC.Enabled || cfg.Auth.OIDC.IssuerURL != "https://idp" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if len(cfg.Auth.AdminGroups) != 2 || cfg.Auth.AdminGroups[1] != "b" {
		t.Fatalf("slice override: %v", cfg.Auth.AdminGroups)
	}
	if cfg.Auth.SessionTTL != 2*time.Hour || cfg.Database.MaxConns != 7 {
		t.Fatalf("typed overrides: %v %v", cfg.Auth.SessionTTL, cfg.Database.MaxConns)
	}
	if len(cfg.Auth.GitLab) != 1 || cfg.Auth.GitLab[0].Name != "gl" {
		t.Fatalf("gitlab override: %+v", cfg.Auth.GitLab)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing session secret error")
	}
	cfg.Auth.SessionSecret = "short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected short secret error")
	}
	cfg.Auth.SessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.Auth.GitLab = []GitLabSpec{{Name: "gl", IssuerURL: "https://gl"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected gitlab audience error without baseURL")
	}
	cfg.Server.BaseURL = "https://e.example.com/"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.GitLabAudience(cfg.Auth.GitLab[0]) != "https://e.example.com" {
		t.Fatalf("audience default: %q", cfg.GitLabAudience(cfg.Auth.GitLab[0]))
	}
}

// The shipped example configuration files must load.
func TestShippedConfigs(t *testing.T) {
	for _, f := range []string{"entrepot.yaml", "entrepot.local.example.yaml"} {
		p := filepath.Join("..", "..", "deploy", "compose", f)
		if _, err := os.Stat(p); err != nil {
			t.Skip(p, "not found")
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !cfg.Auth.OIDC.Enabled || len(cfg.BlobStores) == 0 {
			t.Fatalf("%s: unexpected config %+v", f, cfg)
		}
	}
}
