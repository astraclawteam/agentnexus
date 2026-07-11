#!/bin/sh
set -eu

# Stop-write maintenance deployment for irreversible credential migration 000006.
# Old/new binary overlap is forbidden. The new binary starts isolated from all traffic.

fail() { printf '%s\n' "release-auth: $*" >&2; exit 1; }
require_hook() {
  name=$1
  eval "path=\${$name:-}"
  [ -n "$path" ] || fail "$name is required"
  case "$path" in /*) ;; *) fail "$name must be an absolute path" ;; esac
  [ -f "$path" ] && [ -x "$path" ] || fail "$name must be a regular executable file"
}

[ "${AGENTNEXUS_MAINTENANCE_ACK:-}" = "STOP_WRITES_AND_NO_OVERLAP" ] || fail "maintenance acknowledgement is required"
[ -n "${AGENTNEXUS_POSTGRES_DSN:-}" ] || fail "AGENTNEXUS_POSTGRES_DSN is required"

# The compiled preflight parses the DSN. It must run before any deployment hook.
require_hook AGENTNEXUS_RELEASE_PREFLIGHT_BIN
"$AGENTNEXUS_RELEASE_PREFLIGHT_BIN"

require_hook AGENTNEXUS_RELEASE_STOP_OLD_HOOK
require_hook AGENTNEXUS_RELEASE_BACKUP_HOOK
require_hook AGENTNEXUS_RELEASE_MIGRATE_HOOK
require_hook AGENTNEXUS_RELEASE_START_NEW_ISOLATED_HOOK
require_hook AGENTNEXUS_RELEASE_VERIFY_HOOK
require_hook AGENTNEXUS_RELEASE_STOP_NEW_HOOK
require_hook AGENTNEXUS_RELEASE_OPEN_TRAFFIC_HOOK

phase=stop_old
"$AGENTNEXUS_RELEASE_STOP_OLD_HOOK"

phase=backup
backup_id=$("$AGENTNEXUS_RELEASE_BACKUP_HOOK")
[ -n "$backup_id" ] || fail "backup hook must return a durable backup identifier"
printf '%s\n' "release-auth: backup=$backup_id"

phase=migrate
"$AGENTNEXUS_RELEASE_MIGRATE_HOOK"

phase=start_new_isolated
if ! "$AGENTNEXUS_RELEASE_START_NEW_ISOLATED_HOOK"; then
  if ! "$AGENTNEXUS_RELEASE_STOP_NEW_HOOK"; then
    fail "CRITICAL: isolated start failed and STOP_NEW failed; maintenance must remain active"
  fi
  fail "isolated start failed; new binary stopped; maintenance remains active"
fi

phase=verify
if ! "$AGENTNEXUS_RELEASE_VERIFY_HOOK"; then
  if ! "$AGENTNEXUS_RELEASE_STOP_NEW_HOOK"; then
    fail "CRITICAL: verification failed and STOP_NEW failed; maintenance must remain active"
  fi
  fail "verification failed; isolated new binary stopped; maintenance remains active; restore backup $backup_id before any old release"
fi

phase=open_traffic
if ! "$AGENTNEXUS_RELEASE_OPEN_TRAFFIC_HOOK"; then
  fail "CRITICAL: OPEN_TRAFFIC failed after verification; maintenance state must be inspected manually"
fi

printf '%s\n' "release-auth: traffic opened backup=$backup_id"
