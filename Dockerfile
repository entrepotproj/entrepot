# syntax=docker/dockerfile:1.7

# --- Web UI -----------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY api/openapi.yaml /src/api/openapi.yaml
RUN npm run build

# --- Server -----------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/geoffo-dev/package-repository/internal/api.Version=${VERSION}" \
      -o /out/entrepot ./cmd/entrepot \
 && mkdir -p /out/data

# --- Runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/entrepot /usr/local/bin/entrepot
# Default mount point for file blob stores, writable by the runtime user.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrepot"]
CMD ["serve"]
