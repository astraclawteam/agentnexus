# Shared build for the AgentNexus service binaries; SERVICE selects the cmd.
#
# Build context is the REPOSITORY ROOT (agentnexus/): the service module
# `replace`s ../../sdk/go/*, so both module trees must be inside the context.
# See the repository .dockerignore for what is kept out of it.
ARG GO_IMAGE=golang:1.25-alpine
FROM ${GO_IMAGE} AS build
ARG SERVICE
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0
WORKDIR /src
# The five SDK modules are `replace` targets of the service module, so they have
# to exist before `go mod download` can resolve anything. Downloading against
# the manifests alone keeps that layer -- the only one that touches the network
# -- out of the cache invalidation an ordinary source edit causes.
COPY sdk/go/ sdk/go/
COPY services/agentnexus/go.mod services/agentnexus/go.sum services/agentnexus/
WORKDIR /src/services/agentnexus
# The module and build caches are cache mounts, not layers, so the four service
# images download and compile the shared module tree once between them, and a
# build interrupted by a truncated proxy response resumes from what it already
# has instead of starting over. sharing=locked because the four targets build
# in parallel: without it each one fetches the whole module graph itself, which
# is both wasteful and four times the load on the proxy that truncates.
#
# A failure here fails `build` with a non-zero exit before anything starts. It
# can no longer leave one service exited inside a stack that came up.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download
WORKDIR /src
COPY services/agentnexus/ services/agentnexus/
WORKDIR /src/services/agentnexus
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -o /out/app ./cmd/${SERVICE}

FROM alpine:3.21
# gateway-api resolves the enterprise IdP's OIDC discovery document over HTTPS
# while it builds the router, and gateway-agent reaches llmrouter the same way,
# so a missing root store is a startup failure rather than a degraded feature.
# The dev profile's SSL_CERT_DIR adds the throwaway dev CA by replacing Go's
# certificate DIRECTORY list only; the root certificate FILE installed here is
# still read, which is what keeps every other public TLS target working.
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 10001 nexus
USER nexus
COPY --from=build /out/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
