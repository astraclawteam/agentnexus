.PHONY: generate test-auth release-auth test build contracts-lock contracts-verify

generate:
	sqlc generate

test-auth:
	$(if $(strip $(AGENTNEXUS_E2E_POSTGRES_DSN)),,$(error AGENTNEXUS_E2E_POSTGRES_DSN is required for live PostgreSQL acceptance))
	go test ./internal/browserauth ./internal/deploypreflight ./internal/policy ./internal/approval ./internal/tickets ./internal/app ./cmd/release-preflight ./tests/e2e -count=1

release-auth:
	sh deploy/release-auth.sh

test:
	go test ./...

build:
	go build ./cmd/gateway-api
	go build ./cmd/gateway-agent
	go build ./cmd/connector-worker
	go build ./cmd/connector-agent
	go build ./cmd/release-preflight

# Regenerate the digest lock of the frozen public contract artifacts after a
# deliberate, versioned contract change (also bump api/CHANGELOG.yaml).
contracts-lock:
	go run ./cmd/contract-lock -update

# Fail on any drift between the frozen public contract artifacts and
# api/contract.lock, then prove contract parity.
contracts-verify:
	go run ./cmd/contract-lock -verify
	go test ./internal/app -run 'TestPublicContractParity|TestOpenAPI|TestAuditRequestedAction' -count=1
