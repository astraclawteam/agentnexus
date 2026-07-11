.PHONY: generate test-auth test build

generate:
	sqlc generate

test-auth:
	@test -n "$$AGENTNEXUS_E2E_POSTGRES_DSN" || { echo "AGENTNEXUS_E2E_POSTGRES_DSN is required for live PostgreSQL acceptance" >&2; exit 1; }
	go test ./internal/browserauth ./internal/policy ./internal/approval ./internal/tickets ./internal/app ./tests/e2e -count=1

test:
	go test ./...

build:
	go build ./cmd/gateway-api
	go build ./cmd/gateway-agent
	go build ./cmd/connector-worker
	go build ./cmd/connector-agent
