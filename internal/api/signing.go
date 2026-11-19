package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/entrepotproj/entrepot/internal/api/apigen"
	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/signing"
)

// resigner is implemented by formats with signed metadata (apt, yum): it
// regenerates and re-signs the repository's metadata with the active key.
type resigner interface {
	Resign(ctx context.Context, rp *repo.Repository) error
}

// signedRepo loads a hosted apt/yum repository and checks action.
func (s *Server) signedRepo(w http.ResponseWriter, r *http.Request, name string, action authz.Action) (*repo.Repository, resigner, bool) {
	rp, ok := s.requireRepo(w, r, name, action)
	if !ok {
		return nil, nil, false
	}
	h, found := s.Formats.Get(rp.Format)
	rs, isResigner := h.(resigner)
	if !found || !isResigner || !rp.IsHosted() || s.Signing == nil {
		s.writeErr(w, errBad("signing keys are only available for hosted apt and yum repositories"))
		return nil, nil, false
	}
	return rp, rs, true
}

func (s *Server) signingKeyToAPI(r *http.Request, rp *repo.Repository, k *signing.Key) apigen.SigningKey {
	return apigen.SigningKey{
		Fingerprint: k.Fingerprint,
		Algorithm:   ptr(k.Algorithm),
		PublicKey:   k.PublicArmored,
		Url:         s.URLs.BaseURL(r) + "/repository/" + rp.Name + "/public.key",
		CreatedAt:   k.CreatedAt,
	}
}

func (s *Server) GetSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	rp, _, ok := s.signedRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	k, err := s.Signing.ActiveKey(r.Context(), rp.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.signingKeyToAPI(r, rp, k))
}

func (s *Server) ImportSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	rp, rs, ok := s.signedRepo(w, r, name, authz.Admin)
	if !ok {
		return
	}
	var in apigen.SigningKeyImport
	if !decode(w, r, &in) {
		return
	}
	if deref(in.PrivateKey) == "" {
		s.writeErr(w, errBad("privateKey is required"))
		return
	}
	k, err := s.Signing.Import(r.Context(), rp.ID, deref(in.PrivateKey), deref(in.Passphrase))
	if err != nil {
		if errors.Is(err, signing.ErrInvalidKey) {
			err = errBad(err.Error())
		}
		s.writeErr(w, err)
		return
	}
	s.resign(r, rp, rs)
	s.audit(r, "signingkey.import", rp.Name, map[string]string{"fingerprint": k.Fingerprint, "algorithm": k.Algorithm})
	httpx.WriteJSON(w, http.StatusOK, s.signingKeyToAPI(r, rp, k))
}

func (s *Server) RotateSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	rp, rs, ok := s.signedRepo(w, r, name, authz.Admin)
	if !ok {
		return
	}
	k, err := s.Signing.Rotate(r.Context(), rp.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.resign(r, rp, rs)
	s.audit(r, "signingkey.rotate", rp.Name, map[string]string{"fingerprint": k.Fingerprint, "algorithm": k.Algorithm})
	httpx.WriteJSON(w, http.StatusOK, s.signingKeyToAPI(r, rp, k))
}

// resign regenerates signed metadata; the new key is already active, so a
// failure here is logged (the next upload or delete re-signs) rather than
// reported as a failed rotation.
func (s *Server) resign(r *http.Request, rp *repo.Repository, rs resigner) {
	if err := rs.Resign(context.WithoutCancel(r.Context()), rp); err != nil {
		s.Logger.Error("re-sign repository metadata", "repository", rp.Name, "err", err)
	}
}
