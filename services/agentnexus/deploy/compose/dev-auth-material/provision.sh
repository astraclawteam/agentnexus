#!/bin/sh
# Provision the browser-authentication material the private-dev gateway needs.
#
# gateway-api serves its full surface only when AGENTNEXUS_BROWSER_AUTH_ENABLED
# is true, and config.LoadBrowserAuth then fails closed unless every credential
# below exists with the exact shape the loaders demand:
#
#   - an ID-token signing key: PEM, unencrypted PKCS#8, 0600
#   - one console client secret file per console client: 32-256 printable ASCII
#     bytes, no whitespace, at least 12 distinct bytes, 0600
#   - the upstream IdP client secret file: same shape, a SEPARATE credential
#     domain from the console secrets
#
# It also publishes the trusted first-party SERVICE credential a peer product
# (AgentAtlas) must present. See the comment at that file for why it is a copy
# rather than a value of its own.
#
# The upstream issuer must additionally be reachable over HTTPS at startup
# (browserauth.NewEnterpriseOIDC performs OIDC discovery before the router is
# built), so this also mints a throwaway CA and the dev IdP's server
# certificate. The CA public half is placed in a directory of its own so
# gateway-api can point SSL_CERT_DIR at it without exposing anything private.
#
# Everything lands in a docker volume, never in the repository and never on a
# bind mount: bind-mounted files from a Windows or macOS host do not carry
# 0600, and the loaders reject a secret whose group/other bits are set.
set -eu

dir="${AGENTNEXUS_DEV_AUTH_DIR:-/run/agentnexus/auth}"
marker="$dir/.provisioned"

if [ -f "$marker" ]; then
  # Backfill only: a volume provisioned before the trusted-service credential was
  # published has every other file already, and re-running would otherwise leave
  # a peer product with nothing to copy. Nothing existing is regenerated.
  if [ ! -f "$dir/service-agentatlas-secret" ] && [ -f "$dir/console-agentatlas-secret" ]; then
    echo "dev-auth-material: backfilling the trusted first-party service secret in $dir"
    cp "$dir/console-agentatlas-secret" "$dir/service-agentatlas-secret"
    chmod 0600 "$dir/service-agentatlas-secret"
  fi
  echo "dev-auth-material: already provisioned in $dir"
  exit 0
fi

umask 077
mkdir -p "$dir" "$dir/trust" "$dir/idp"

echo "dev-auth-material: minting a development CA"
openssl ecparam -genkey -name prime256v1 -out "$dir/ca.key" 2>/dev/null
openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 3650 \
  -subj "/CN=agentnexus-private-dev-ca" -out "$dir/trust/dev-ca.crt"

echo "dev-auth-material: issuing the dev IdP server certificate"
openssl ecparam -genkey -name prime256v1 -out "$dir/idp/tls.key" 2>/dev/null
openssl req -new -key "$dir/idp/tls.key" -subj "/CN=idp" -out "$dir/idp/tls.csr"
cat > "$dir/idp/tls.ext" <<'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:idp, DNS:localhost, IP:127.0.0.1
EXT
openssl x509 -req -in "$dir/idp/tls.csr" -CA "$dir/trust/dev-ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -days 3650 -sha256 -extfile "$dir/idp/tls.ext" -out "$dir/idp/tls.crt"
rm -f "$dir/idp/tls.csr" "$dir/idp/tls.ext" "$dir/trust/dev-ca.srl"

echo "dev-auth-material: generating the ID-token signing key"
openssl genpkey -algorithm ed25519 -out "$dir/oidc-signing-key.pem"

# 48 random bytes render as 64 base64 characters: inside the 32-256 byte window,
# printable ASCII throughout, and far past the 12-distinct-byte floor. The
# trailing newline is stripped because the loaders reject any byte below 0x21.
echo "dev-auth-material: generating client secrets"
openssl rand -base64 48 | tr -d '\n' > "$dir/console-agentatlas-secret"
openssl rand -base64 48 | tr -d '\n' > "$dir/upstream-client-secret"

# The TRUSTED FIRST-PARTY SERVICE credential, published as a counterpart file so
# a peer product has something concrete to consume.
#
# It is a COPY of the console client secret, not a fresh value, because in this
# build the two are one credential. gateway-runtime.yaml declares
# trustedServiceSecret and consoleClientSecret as separate security schemes, but
# consoleServiceCredentialVerifier (internal/app/browser_auth.go) verifies BOTH
# against OIDCConfig.ConsoleCredentials -- the hashed set loaded from
# AGENTNEXUS_OIDC_CONSOLE_CLIENT_SECRET_FILES_JSON. A separately generated value
# here would authenticate nothing and would be a lie about what AgentNexus
# accepts. Enrolment is therefore an out-of-band operator act: there is no API
# that mints a service credential (POST /v1/agent-clients registers a client's
# publisher/product for certification; it neither takes nor returns a secret,
# and it requires this very credential to call).
#
# This file existing is the point. Without it a joint deployment had no
# AgentNexus-side artefact to copy, each side generated its own, both looked
# correctly configured, and every first-party call 401'd forever.
#
# The day the two schemes get separate credential stores, this stops being a
# copy and starts being generated -- and this is the file to change.
echo "dev-auth-material: publishing the trusted first-party service secret (== the agentatlas console client secret)"
cp "$dir/console-agentatlas-secret" "$dir/service-agentatlas-secret"

chmod 0600 "$dir/ca.key" "$dir/idp/tls.key" "$dir/idp/tls.crt" \
  "$dir/oidc-signing-key.pem" "$dir/console-agentatlas-secret" "$dir/upstream-client-secret" \
  "$dir/service-agentatlas-secret"
# The trust directory is read wholesale by Go's root loader, so it holds the CA
# certificate and nothing else.
chmod 0755 "$dir/trust"
chmod 0644 "$dir/trust/dev-ca.crt"

printf 'agentnexus private-dev browser auth material\n' > "$marker"
echo "dev-auth-material: provisioned $dir"
