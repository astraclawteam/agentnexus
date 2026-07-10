.PHONY: generate test build

generate:
	sqlc generate

test:
	go test ./...

build:
	go build ./cmd/gateway-api
	go build ./cmd/gateway-agent
	go build ./cmd/connector-worker
	go build ./cmd/connector-agent
