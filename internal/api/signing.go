package api

import (
	"net/http"
)

// Phase 2 stubs: implemented by the Apt/Yum agent.

func (s *Server) GetSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) ImportSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) RotateSigningKey(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}
