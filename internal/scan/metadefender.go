package scan

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/entrepotproj/entrepot/internal/scan/drivers"
)

// FileHTTP returns the HTTP client for file scanners. Uploads of large
// files have no total timeout (the job's context bounds them); responses
// must start within two minutes. Clients are shared per CA bundle so
// connections are reused across jobs.
func (s *Service) fileHTTP(caPEM string) (*http.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.fileClients[caPEM]; ok {
		return c, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 2 * time.Minute
	tr.MaxIdleConnsPerHost = drivers.MaxConcurrency
	if caPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("metadefender.caCertificate contains no PEM certificates")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c := &http.Client{Transport: tr}
	if s.fileClients == nil {
		s.fileClients = map[string]*http.Client{}
	}
	s.fileClients[caPEM] = c
	return c, nil
}

// metaDefender builds the driver of a MetaDefender scanner.
func (s *Service) metaDefender(ls *loadedScanner) (*drivers.MetaDefender, error) {
	c := ls.Cfg.MetaDefender
	if c == nil || c.URL == "" {
		return nil, errors.New("metadefender.url is not set")
	}
	hc, err := s.fileHTTP(c.CACertificate)
	if err != nil {
		return nil, err
	}
	return &drivers.MetaDefender{URL: c.URL, APIKey: c.APIKey, Rule: c.Rule, Concurrency: c.Parallel(),
		HashLookup: c.LookupHashes(), MaxResultAge: c.ResultAge(), WebURL: c.WebURL, Client: hc,
		PollMin: s.FilePollMin, PollMax: s.FilePollMax, BusyBackoff: s.FileBusyBackoff}, nil
}
