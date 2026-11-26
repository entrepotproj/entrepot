package api

import (
	"context"
	"slices"

	"github.com/entrepotproj/entrepot/internal/api/apigen"
	"github.com/entrepotproj/entrepot/internal/repo"
)

var severities = []string{"critical", "high", "medium", "low"}

// phase2Settings converts and validates the optional scan/cleanup/routing,
// Apt/Yum and group settings of a repository request into cfg.
func (s *Server) phase2Settings(ctx context.Context, in apigen.RepositoryInput, cfg *repo.Config) error {
	if sc := in.Scan; sc != nil {
		c := &repo.ScanConfig{
			OnUpload:          sc.OnUpload,
			OnProxyFetch:      sc.OnProxyFetch,
			BlockUntilScanned: deref(sc.BlockUntilScanned),
			BlockOnError:      deref(sc.BlockOnError),
			HoldSeconds:       deref(sc.HoldSeconds),
			Distro:            deref(sc.Distro),
		}
		if c.HoldSeconds < 0 || c.HoldSeconds > 600 {
			return errBad("scan.holdSeconds must be between 0 and 600")
		}
		if sc.Scanners != nil {
			for _, name := range *sc.Scanners {
				ok, err := s.Store.NamedExists(ctx, "scanners", name)
				if err != nil {
					return err
				}
				if !ok {
					return errBad("unknown scanner " + name)
				}
				if !slices.Contains(c.Scanners, name) {
					c.Scanners = append(c.Scanners, name)
				}
			}
		}
		if sc.Mode != nil {
			c.Mode = string(*sc.Mode)
			if c.Mode != "off" && c.Mode != "warn" && c.Mode != "quarantine" {
				return errBad("scan.mode must be off, warn or quarantine")
			}
		}
		if sc.SeverityThreshold != nil {
			c.SeverityThreshold = string(*sc.SeverityThreshold)
			if !slices.Contains(severities, c.SeverityThreshold) {
				return errBad("scan.severityThreshold must be critical, high, medium or low")
			}
		}
		cfg.Scan = c
	}
	if cl := in.Cleanup; cl != nil && cl.Policies != nil && len(*cl.Policies) > 0 {
		c := &repo.CleanupConfig{}
		for _, name := range *cl.Policies {
			ok, err := s.Store.NamedExists(ctx, "cleanup_policies", name)
			if err != nil {
				return err
			}
			if !ok {
				return errBad("unknown cleanup policy " + name)
			}
			if !slices.Contains(c.Policies, name) {
				c.Policies = append(c.Policies, name)
			}
		}
		cfg.Cleanup = c
	}
	if cfg.Proxy != nil && in.Proxy != nil && deref(in.Proxy.RoutingRule) != "" {
		name := *in.Proxy.RoutingRule
		ok, err := s.Store.NamedExists(ctx, "routing_rules", name)
		if err != nil {
			return err
		}
		if !ok {
			return errBad("unknown routing rule " + name)
		}
		cfg.Proxy.RoutingRule = name
	}
	if cfg.Group != nil && in.Group != nil {
		cfg.Group.PreferHosted = in.Group.PreferHosted
	}
	if cfg.Hosted != nil && in.Hosted != nil {
		if a := in.Hosted.Apt; a != nil && in.Format == "apt" {
			ac := &repo.AptConfig{}
			for _, d := range deref(a.Distributions) {
				if d.Name == "" {
					return errBad("hosted.apt.distributions[].name is required")
				}
				ac.Distributions = append(ac.Distributions, repo.AptDistribution{
					Name: d.Name, Components: deref(d.Components), Architectures: deref(d.Architectures),
					Origin: deref(d.Origin), Label: deref(d.Label),
				})
			}
			cfg.Hosted.Apt = ac
		}
		if y := in.Hosted.Yum; y != nil && in.Format == "yum" {
			depth := deref(y.RepodataDepth)
			if depth < 0 || depth > 5 {
				return errBad("hosted.yum.repodataDepth must be between 0 and 5")
			}
			cfg.Hosted.Yum = &repo.YumConfig{RepodataDepth: depth}
		}
	}
	return nil
}

// phase2ToAPI fills the optional settings of a repository response.
func phase2ToAPI(rp *repo.Repository, out *apigen.Repository) {
	if c := rp.Cfg.Scan; c != nil {
		mode := apigen.ScanSettingsMode(c.EffectiveMode())
		thr := apigen.ScanSettingsSeverityThreshold(c.Threshold())
		up, px := c.ScanOnUpload(), c.ScanOnProxyFetch()
		out.Scan = &apigen.ScanSettings{
			Scanners: ptr(nonNil(c.Scanners)), Mode: &mode, SeverityThreshold: &thr,
			OnUpload: &up, OnProxyFetch: &px, BlockUntilScanned: ptr(c.BlockUntilScanned),
			BlockOnError: ptr(c.BlockOnError), HoldSeconds: ptr(c.HoldSeconds),
		}
		if c.Distro != "" {
			out.Scan.Distro = ptr(c.Distro)
		}
	}
	if c := rp.Cfg.Cleanup; c != nil {
		out.Cleanup = &apigen.CleanupSettings{Policies: ptr(nonNil(c.Policies))}
	}
	if p := rp.Cfg.Proxy; p != nil && p.RoutingRule != "" && out.Proxy != nil {
		out.Proxy.RoutingRule = ptr(p.RoutingRule)
	}
	if g := rp.Cfg.Group; g != nil && out.Group != nil {
		out.Group.PreferHosted = ptr(g.PrefersHosted())
	}
	if h := rp.Cfg.Hosted; h != nil && out.Hosted != nil {
		if h.Apt != nil {
			var ds []apigen.AptDistribution
			for _, d := range h.Apt.Distributions {
				ad := apigen.AptDistribution{Name: d.Name, Components: ptr(nonNil(d.Components)), Architectures: ptr(nonNil(d.Architectures))}
				if d.Origin != "" {
					ad.Origin = ptr(d.Origin)
				}
				if d.Label != "" {
					ad.Label = ptr(d.Label)
				}
				ds = append(ds, ad)
			}
			out.Hosted.Apt = &apigen.AptHostedSettings{Distributions: ptr(nonNil(ds))}
		}
		if h.Yum != nil {
			out.Hosted.Yum = &apigen.YumHostedSettings{RepodataDepth: ptr(h.Yum.RepodataDepth)}
		}
	}
}
