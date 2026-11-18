package api

import (
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
)

// Phase 2 stubs: implemented by the scanning agent.

func (s *Server) ScanComponent(w http.ResponseWriter, r *http.Request, id string) { notImplemented(w) }

func (s *Server) GetComponentScans(w http.ResponseWriter, r *http.Request, id string) {
	notImplemented(w)
}

func (s *Server) ListScanJobs(w http.ResponseWriter, r *http.Request, params apigen.ListScanJobsParams) {
	notImplemented(w)
}

func (s *Server) GetScanJobArtifact(w http.ResponseWriter, r *http.Request, id string, params apigen.GetScanJobArtifactParams) {
	notImplemented(w)
}

func (s *Server) SubmitScanJobResult(w http.ResponseWriter, r *http.Request, id string, params apigen.SubmitScanJobResultParams) {
	notImplemented(w)
}

func (s *Server) ListScanners(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) CreateScanner(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) DeleteScanner(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) GetScanner(w http.ResponseWriter, r *http.Request, name string) { notImplemented(w) }

func (s *Server) UpdateScanner(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) TestScanner(w http.ResponseWriter, r *http.Request, name string) { notImplemented(w) }

func (s *Server) ListWaivers(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) CreateWaiver(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) DeleteWaiver(w http.ResponseWriter, r *http.Request, id string) { notImplemented(w) }

func (s *Server) GetWaiver(w http.ResponseWriter, r *http.Request, id string) { notImplemented(w) }

func (s *Server) UpdateWaiver(w http.ResponseWriter, r *http.Request, id string) { notImplemented(w) }
