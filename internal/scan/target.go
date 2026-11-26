package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/entrepotproj/entrepot/internal/formats/docker"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/scan/drivers"
	"github.com/entrepotproj/entrepot/internal/store"
)

const kindUnsupported = "unsupported"

// maxPlatforms bounds the platform images of an index that are scanned.
const maxPlatforms = 8

// target is what a job scans.
type target struct {
	kind        string // drivers.KindPackage, KindImage, KindFiles or kindUnsupported
	reason      string // why unsupported
	description string

	// package targets
	pkg    drivers.Package
	purl   string
	distro string

	// image targets: the tag's manifest digest and the platform manifests
	// to scan.
	image     string
	digest    string
	platforms []docker.ImageManifest
	// skipped are platform manifests of the index left out because a proxy
	// has not cached them; pulling one rescans the image (strict verdicts).
	skipped []string

	// file targets (scanners that read content)
	files []drivers.File
}

// imageExporter is implemented by the Docker format handler.
type imageExporter interface {
	ImageManifests(ctx context.Context, rp *repo.Repository, image, digest string) ([]docker.ImageManifest, error)
	ExportImages(ctx context.Context, rp *repo.Repository, image string, digests []string, dir string) error
}

// layerSource lists and opens image layers (Docker format handler).
type layerSource interface {
	ImageLayers(ctx context.Context, rp *repo.Repository, image string, manifests []docker.ImageManifest) ([]docker.Layer, error)
	OpenBlob(ctx context.Context, rp *repo.Repository, image, digest string) (io.ReadCloser, error)
}

func (s *Service) layerSource() (layerSource, error) {
	h, ok := s.Formats.Get("docker")
	if !ok {
		return nil, errors.New("docker format is not enabled")
	}
	l, ok := h.(layerSource)
	if !ok {
		return nil, errors.New("docker format cannot list image layers")
	}
	return l, nil
}

func (s *Service) imageExporter() (imageExporter, error) {
	h, ok := s.Formats.Get("docker")
	if !ok {
		return nil, errors.New("docker format is not enabled")
	}
	e, ok := h.(imageExporter)
	if !ok {
		return nil, errors.New("docker format cannot export images")
	}
	return e, nil
}

func attrString(attrs map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := attrs[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// rpmNamespace derives the purl namespace of RPMs from a distro such as
// rocky-9, rhel-9, almalinux-9, fedora-40, centos-7, amazon-2023.
func rpmNamespace(distro string) string {
	name, _ := drivers.OSRelease(distro)
	switch name {
	case "rhel", "redhat", "":
		return "redhat"
	case "almalinux", "alma":
		return "alma"
	case "amzn", "amazonlinux", "amazon":
		return "amazon"
	case "opensuse", "opensuse-leap", "sles", "suse":
		return "opensuse"
	case "ol", "oraclelinux", "oracle":
		return "oracle"
	}
	return name
}

// debNamespace is debian or ubuntu.
func debNamespace(distro string) string {
	if name, _ := drivers.OSRelease(distro); name == "ubuntu" {
		return "ubuntu"
	}
	return "debian"
}

// PackageFor returns the package identity of a component, or ok=false when
// the format cannot be scanned as a package.
func PackageFor(format, name, version string, attrs map[string]any, distro string) (drivers.Package, bool) {
	switch format {
	case "npm":
		p := drivers.Package{Type: "npm", Name: name, Version: version}
		if strings.HasPrefix(name, "@") {
			if ns, n, ok := strings.Cut(name, "/"); ok {
				p.Namespace, p.Name = ns, n
			}
		}
		return p, true
	case "pypi":
		n := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name))
		return drivers.Package{Type: "pypi", Name: n, Version: version}, true
	case "apt":
		q := map[string]string{"arch": attrString(attrs, "architecture", "arch")}
		if distro != "" {
			q["distro"] = distro
		}
		return drivers.Package{Type: "deb", Namespace: debNamespace(distro), Name: name, Version: version, Qualifiers: q}, true
	case "yum":
		q := map[string]string{"arch": attrString(attrs, "arch", "architecture")}
		if distro != "" {
			q["distro"] = distro
		}
		v := version
		if e, rest, ok := strings.Cut(version, ":"); ok {
			q["epoch"], v = e, rest
		} else if e := attrString(attrs, "epoch"); e != "" && e != "0" {
			q["epoch"] = e
		}
		return drivers.Package{Type: "rpm", Namespace: rpmNamespace(distro), Name: name, Version: v, Qualifiers: q}, true
	}
	return drivers.Package{}, false
}

// resolveTarget decides what to scan for a component. It reads manifests
// for Docker images but materialises nothing.
func (s *Service) resolveTarget(ctx context.Context, rp *repo.Repository, comp *store.Component) (*target, error) {
	var attrs map[string]any
	_ = json.Unmarshal(comp.Attrs, &attrs)
	distro := ""
	if rp.Cfg.Scan != nil {
		distro = rp.Cfg.Scan.Distro
	}
	switch comp.Format {
	case "docker":
		a, err := s.Store.GetAsset(ctx, comp.RepositoryID, comp.Name+"/_tags/"+comp.Version)
		if err != nil {
			return nil, fmt.Errorf("tag %s: %w", describe(comp), err)
		}
		exp, err := s.imageExporter()
		if err != nil {
			return nil, err
		}
		ms, err := exp.ImageManifests(ctx, rp, comp.Name, a.Digest)
		if err != nil {
			return nil, err
		}
		tg := &target{kind: drivers.KindImage, image: comp.Name, digest: a.Digest,
			description: comp.Name + ":" + comp.Version + "@" + a.Digest}
		tg.platforms = selectPlatforms(rp, ms)
		tg.skipped = uncachedPlatforms(rp, ms, tg.platforms)
		if len(tg.platforms) == 0 {
			return &target{kind: kindUnsupported, description: tg.description,
				reason: "the image index has no platform images"}, nil
		}
		return tg, nil
	case "apt", "yum", "npm", "pypi":
		p, _ := PackageFor(comp.Format, comp.Name, comp.Version, attrs, distro)
		purl := p.PURL()
		tg := &target{kind: drivers.KindPackage, pkg: p, purl: purl, distro: distro, description: purl}
		if (comp.Format == "apt" || comp.Format == "yum") && distro == "" {
			// Without a distribution OS packages cannot be matched reliably;
			// scanners still try (Trivy falls back to the purl namespace).
			s.Logger.Debug("scanning OS package without scan.distro", "repository", rp.Name, "component", describe(comp))
		}
		return tg, nil
	default:
		return &target{kind: kindUnsupported, description: describe(comp),
			reason: comp.Format + " components cannot be scanned"}, nil
	}
}

// uncachedPlatforms lists the platform manifests of a proxy's index that
// are not scanned because they are not cached yet (not those beyond the
// platform limit).
func uncachedPlatforms(rp *repo.Repository, all, selected []docker.ImageManifest) []string {
	if !rp.IsProxy() {
		return nil
	}
	chosen := map[string]bool{}
	for _, m := range selected {
		chosen[m.Digest] = true
	}
	var out []string
	for _, m := range all {
		if !chosen[m.Digest] && !m.Local {
			out = append(out, m.Digest)
		}
	}
	return out
}

// selectPlatforms picks the platform images of an index to scan: all of
// them for hosted repositories; for proxies only those already cached (or
// linux/amd64 when none is), so scanning does not pull every platform.
func selectPlatforms(rp *repo.Repository, ms []docker.ImageManifest) []docker.ImageManifest {
	if len(ms) == 1 && ms[0].Platform == "" {
		return ms
	}
	var out []docker.ImageManifest
	if rp.IsProxy() {
		for _, m := range ms {
			if m.Local {
				out = append(out, m)
			}
		}
		if len(out) == 0 {
			for _, m := range ms {
				if m.Platform == "linux/amd64" {
					out = append(out, m)
					break
				}
			}
		}
		if len(out) == 0 && len(ms) > 0 {
			out = append(out, ms[0])
		}
	} else {
		out = ms
	}
	if len(out) > maxPlatforms {
		out = out[:maxPlatforms]
	}
	return out
}

// maxFiles bounds the files of a component sent to a file scanner.
const maxFiles = 1000

// fileTarget lists the files of a component for scanners that read content
// (every format: the component's assets except sidecars derived from the
// package, such as PyPI .metadata and Helm .prov files). Content is opened
// only when the scanner needs it.
func (s *Service) fileTarget(ctx context.Context, rp *repo.Repository, comp *store.Component) (*target, error) {
	if comp.Format == "docker" {
		return s.layerTarget(ctx, rp, comp)
	}
	assets, err := s.Store.ListComponentAssets(ctx, comp.ID)
	if err != nil {
		return nil, err
	}
	tg := &target{kind: drivers.KindFiles, description: describe(comp)}
	for _, a := range assets {
		if repo.IsSidecar(comp.Format, a.Path) {
			continue
		}
		if len(tg.files) == maxFiles {
			return nil, fmt.Errorf("%s has more than %d files", describe(comp), maxFiles)
		}
		a := a
		name := a.Path
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		sum := ""
		if d, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
			sum = d
		}
		tg.files = append(tg.files, drivers.File{Name: name, Label: a.Path, Size: a.Size, SHA256: sum,
			MediaType: a.ContentType, Open: func(ctx context.Context) (io.ReadCloser, error) {
				return s.Repos.Open(ctx, rp, a)
			}})
	}
	if len(tg.files) == 0 {
		return &target{kind: kindUnsupported, description: tg.description, reason: "the component has no files"}, nil
	}
	return tg, nil
}

// layerTarget lists the layers of a Docker image (the platforms chosen as
// for image scans) as files. Each layer is sent once even when platforms
// share it; its sha256 is the blob digest, so a scanner that knows the
// layer by hash never needs it fetched from the upstream.
func (s *Service) layerTarget(ctx context.Context, rp *repo.Repository, comp *store.Component) (*target, error) {
	img, err := s.resolveTarget(ctx, rp, comp)
	if err != nil || img.kind != drivers.KindImage {
		return img, err
	}
	src, err := s.layerSource()
	if err != nil {
		return nil, err
	}
	layers, err := src.ImageLayers(ctx, rp, comp.Name, img.platforms)
	if err != nil {
		return nil, err
	}
	if len(layers) > maxFiles {
		return nil, fmt.Errorf("%s has more than %d layers", describe(comp), maxFiles)
	}
	tg := &target{kind: drivers.KindFiles, description: img.description, image: img.image, digest: img.digest,
		platforms: img.platforms, skipped: img.skipped}
	for _, l := range layers {
		l := l
		hexd, _ := strings.CutPrefix(l.Digest, "sha256:")
		if hexd == l.Digest {
			hexd = "" // not a sha256 digest: never matched by hash
		}
		short := strings.TrimPrefix(l.Digest, "sha256:")
		if len(short) > 12 {
			short = short[:12]
		}
		label := "layer sha256:" + short
		if len(l.Platforms) > 0 {
			label += " (" + strings.Join(l.Platforms, ", ") + ")"
		}
		tg.files = append(tg.files, drivers.File{Name: "layer-" + short + layerExt(l.MediaType), Label: label, Size: l.Size,
			SHA256: hexd, MediaType: l.MediaType, Open: func(ctx context.Context) (io.ReadCloser, error) {
				return src.OpenBlob(ctx, rp, comp.Name, l.Digest)
			}})
	}
	if len(tg.files) == 0 {
		return &target{kind: kindUnsupported, description: tg.description, reason: "the image has no layers"}, nil
	}
	return tg, nil
}

// layerExt names a layer file after its compression (scanners use the
// name as a hint).
func layerExt(mediaType string) string {
	switch {
	case strings.HasSuffix(mediaType, "+zstd") || strings.HasSuffix(mediaType, ".zstd"):
		return ".tar.zst"
	case strings.HasSuffix(mediaType, "gzip"):
		return ".tar.gz"
	case strings.HasSuffix(mediaType, ".tar") || strings.HasSuffix(mediaType, "layer.v1.tar"):
		return ".tar"
	}
	return ".tar.gz"
}
