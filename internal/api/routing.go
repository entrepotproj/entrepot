package api

import (
	"net/http"
)

// Phase 2 stubs: implemented by the routing agent.

func (s *Server) ListRoutingRules(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) CreateRoutingRule(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) DeleteRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) GetRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) UpdateRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) TestRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}
