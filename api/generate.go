// Package api holds the OpenAPI specification and code generation config.
package api

import _ "embed"

//go:generate go tool oapi-codegen -config server.cfg.yaml openapi.yaml
//go:generate go tool oapi-codegen -config client.cfg.yaml openapi.yaml

// Spec is the raw OpenAPI document served at /api/openapi.yaml.
//
//go:embed openapi.yaml
var Spec []byte
