VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/entrepotproj/entrepot/internal/api.Version=$(VERSION)
IMAGE   ?= ghcr.io/entrepotproj/entrepot:$(VERSION)
# Postgres used by integration tests (the test user must be able to CREATE DATABASE).
TEST_DATABASE_URL ?= postgres://postgres@localhost:5432/postgres?sslmode=disable

.PHONY: all build ui gen test test-unit test-integration lint fmt docker helm-lint dev-up dev-down run clean

all: ui build

## build: compile the server (embeds whatever is in web/dist)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/entrepot ./cmd/entrepot

## ui: build the React UI into web/dist
ui:
	cd web && npm ci --no-audit --no-fund && npm run build

## gen: regenerate API server/client code and UI types from api/openapi.yaml
gen:
	cd api && go generate ./...
	cd web && npm run gen:api

## test: unit + integration tests (integration tests need Postgres)
test:
	ENTREPOT_TEST_DATABASE_URL="$(TEST_DATABASE_URL)" go test -race ./...

test-unit:
	go test ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || (echo "gofmt needed:"; gofmt -l $$(git ls-files '*.go'); exit 1)

fmt:
	gofmt -w $$(git ls-files '*.go')

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

helm-lint:
	helm lint deploy/helm/entrepot --set database.url=postgres://example
	for f in deploy/helm/entrepot/examples/*.yaml; do helm template t deploy/helm/entrepot -f $$f >/dev/null || exit 1; done

## dev-up: start Postgres, MinIO, Keycloak and Entrepot with docker compose
dev-up:
	docker compose -f deploy/compose/docker-compose.yaml up -d --build

dev-down:
	docker compose -f deploy/compose/docker-compose.yaml down

## run: run locally against deploy/compose services (Postgres on :5432)
run: build
	./bin/entrepot serve -config deploy/compose/entrepot.local.example.yaml

clean:
	rm -rf bin dist
