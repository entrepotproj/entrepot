package drivers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"
)

// Package identifies a package for vulnerability matching.
type Package struct {
	// Type is the purl type: npm, pypi, deb, rpm, ...
	Type      string
	Namespace string
	Name      string
	Version   string
	// Qualifiers such as arch, distro, epoch.
	Qualifiers map[string]string
}

// PURL renders the package URL (https://github.com/package-url/purl-spec).
func (p Package) PURL() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		for _, seg := range strings.Split(p.Namespace, "/") {
			b.WriteString(purlEscape(seg))
			b.WriteByte('/')
		}
	}
	b.WriteString(purlEscape(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(purlEscape(p.Version))
	}
	keys := make([]string, 0, len(p.Qualifiers))
	for k, v := range p.Qualifiers {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(purlEscape(p.Qualifiers[k]))
	}
	return b.String()
}

func purlEscape(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

// OSRelease splits a distro such as "debian-12" or "ubuntu-24.04" into
// name and version.
func OSRelease(distro string) (name, version string) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	if i := strings.LastIndexAny(distro, "-:"); i > 0 {
		return distro[:i], distro[i+1:]
	}
	return distro, ""
}

type cdxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// SBOM renders a minimal CycloneDX 1.5 document describing one package
// (and, for OS packages, the operating system it belongs to). Both
// `trivy sbom` and `grype sbom:` accept it.
func SBOM(p Package, distro string) ([]byte, error) {
	purl := p.PURL()
	root := cdxComponent{BOMRef: "entrepot-target", Type: "application", Name: "entrepot-scan-target"}
	pkg := cdxComponent{BOMRef: purl, Type: "library", Name: p.Name, Version: p.Version, PURL: purl}
	if p.Type == "npm" && p.Namespace != "" {
		pkg.Group = p.Namespace
	}
	comps := []cdxComponent{}
	deps := []cdxDependency{}
	if osName, osVersion := OSRelease(distro); (p.Type == "deb" || p.Type == "rpm" || p.Type == "apk") && osName != "" {
		if osName == "rhel" {
			osName = "redhat"
		}
		comps = append(comps, cdxComponent{BOMRef: "entrepot-os", Type: "operating-system", Name: osName, Version: osVersion})
		deps = append(deps, cdxDependency{Ref: root.BOMRef, DependsOn: []string{"entrepot-os"}},
			cdxDependency{Ref: "entrepot-os", DependsOn: []string{purl}})
	} else {
		deps = append(deps, cdxDependency{Ref: root.BOMRef, DependsOn: []string{purl}})
	}
	comps = append(comps, pkg)
	deps = append(deps, cdxDependency{Ref: purl, DependsOn: []string{}})
	var serial [16]byte
	_, _ = rand.Read(serial[:])
	serial[6] = serial[6]&0x0f | 0x40
	serial[8] = serial[8]&0x3f | 0x80
	h := hex.EncodeToString(serial[:])
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:],
		"version":      1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     map[string]any{"components": []any{map[string]string{"type": "application", "name": "entrepot"}}},
			"component": root,
		},
		"components":   comps,
		"dependencies": deps,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(doc)
	return buf.Bytes(), err
}

// WriteSBOM writes SBOM(p, distro) to path.
func WriteSBOM(path string, p Package, distro string) error {
	b, err := SBOM(p, distro)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
