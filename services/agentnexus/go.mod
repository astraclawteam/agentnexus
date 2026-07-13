module github.com/astraclawteam/agentnexus/services/agentnexus

go 1.25.0

require (
	github.com/astraclawteam/agentnexus/sdk/go/connector v0.0.0
	github.com/astraclawteam/agentnexus/sdk/go/runtime v0.0.0
	github.com/astraclawteam/agentnexus/sdk/go/secretprovider v0.0.0
	github.com/astraclawteam/agentnexus/sdk/go/transportsecurity v0.0.0
	github.com/coreos/go-oidc/v3 v3.20.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/jackc/pgx/v5 v5.10.0
	github.com/nats-io/nats.go v1.52.0
	github.com/xuri/excelize/v2 v2.10.1
	golang.org/x/oauth2 v0.36.0
	google.golang.org/adk/v2 v2.0.0
	google.golang.org/genai v1.57.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/astraclawteam/agentnexus/sdk/go/connector => ../../sdk/go/connector

replace github.com/astraclawteam/agentnexus/sdk/go/runtime => ../../sdk/go/runtime

replace github.com/astraclawteam/agentnexus/sdk/go/secretprovider => ../../sdk/go/secretprovider

replace github.com/astraclawteam/agentnexus/sdk/go/transportsecurity => ../../sdk/go/transportsecurity

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.15 // indirect
	github.com/googleapis/gax-go/v2 v2.22.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/richardlehane/mscfb v1.0.6 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/tiendc/go-deepcopy v1.7.2 // indirect
	github.com/xuri/efp v0.0.1 // indirect
	github.com/xuri/nfp v0.0.2-0.20250530014748-2ddeb826f9a9 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/api v0.279.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260511170946-3700d4141b60 // indirect
	google.golang.org/grpc v1.81.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
