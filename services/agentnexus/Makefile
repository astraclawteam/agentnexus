.PHONY: generate test-auth release-auth test build

generate:
	sqlc generate

test-auth:
	$(if $(strip $(AGENTNEXUS_E2E_POSTGRES_DSN)),,$(error AGENTNEXUS_E2E_POSTGRES_DSN is required for live PostgreSQL acceptance))
	go test ./internal/browserauth ./internal/policy ./internal/approval ./internal/tickets ./internal/app ./tests/e2e -count=1

release-auth:
	sh deploy/release-auth.sh

test:
	go test ./...

build:
	go build ./cmd/gateway-api
	go build ./cmd/gateway-agent
	go build ./cmd/connector-worker
	go build ./cmd/connector-agent
