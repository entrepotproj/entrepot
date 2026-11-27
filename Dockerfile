# syntax=docker/dockerfile:1.7
#
# Targets:
#   (default)  distroless image with the entrepot server
#   scanner    Debian-based image with trivy and grype, for `entrepot scan-worker`
#              docker build --target scanner -t entrepot-scanner .

# The UI, the Go binary and the scanner CLI downloads are built on the build
# machine's platform ($BUILDPLATFORM) and cross-compiled, so multi-platform
# builds (linux/arm64 on amd64 runners) never run npm or the Go toolchain
# under QEMU emulation, which is slow and can crash.

# --- Web UI -----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY api/openapi.yaml /src/api/openapi.yaml
RUN npm run build

# --- Server -----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/entrepotproj/entrepot/internal/api.Version=${VERSION}" \
      -o /out/entrepot ./cmd/entrepot \
 && mkdir -p /out/data

# --- Scanner CLIs (checksum-verified release binaries) ----------------------
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tools
ARG TARGETARCH=amd64
# renovate: datasource=github-releases depName=aquasecurity/trivy extractVersion=^v(?<version>.+)$
ARG TRIVY_VERSION=0.76.0
# renovate: datasource=github-releases depName=anchore/grype extractVersion=^v(?<version>.+)$
ARG GRYPE_VERSION=0.84.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/tools
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) T_ARCH=Linux-64bit; G_ARCH=linux_amd64 ;; \
      arm64) T_ARCH=Linux-ARM64; G_ARCH=linux_arm64 ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 1 ;; \
    esac; \
    T=trivy_${TRIVY_VERSION}_${T_ARCH}.tar.gz; \
    curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/$T; \
    curl -fsSL -o trivy.sha256 https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt; \
    grep " $T\$" trivy.sha256 | sha256sum -c -; \
    tar -xzf $T trivy; \
    G=grype_${GRYPE_VERSION}_${G_ARCH}.tar.gz; \
    curl -fsSLO https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/$G; \
    curl -fsSL -o grype.sha256 https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt; \
    grep " $G\$" grype.sha256 | sha256sum -c -; \
    tar -xzf $G grype; \
    install -m 0755 trivy grype /usr/local/bin/

# --- Scanner worker image ----------------------------------------------------
FROM debian:bookworm-slim AS scanner
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 65532 --create-home --home-dir /home/nonroot nonroot \
 && mkdir -p /data /cache && chown 65532:65532 /data /cache
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/grype /usr/local/bin/
COPY --from=build /out/entrepot /usr/local/bin/entrepot
ENV TRIVY_CACHE_DIR=/cache/trivy GRYPE_DB_CACHE_DIR=/cache/grype
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/entrepot"]
CMD ["scan-worker"]

# --- Runtime (default) --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/entrepot /usr/local/bin/entrepot
# Default mount point for file blob stores, writable by the runtime user.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrepot"]
CMD ["serve"]
