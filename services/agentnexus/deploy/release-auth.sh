#!/bin/sh
set -eu

# Stop-write maintenance deployment for irreversible credential migration 000006.
# Old/new binary overlap is forbidden because old binaries treat database ids as bearers.

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
case "$AGENTNEXUS_POSTGRES_DSN" in *sslmode=disable*) fail "production DSN must require TLS" ;; esac

require_hook AGENTNEXUS_RELEASE_STOP_OLD_HOOK
require_hook AGENTNEXUS_RELEASE_BACKUP_HOOK
require_hook AGENTNEXUS_RELEASE_MIGRATE_HOOK
require_hook AGENTNEXUS_RELEASE_START_NEW_HOOK
require_hook AGENTNEXUS_RELEASE_VERIFY_HOOK

phase=stop_old
"$AGENTNEXUS_RELEASE_STOP_OLD_HOOK"

phase=backup
backup_id=$("$AGENTNEXUS_RELEASE_BACKUP_HOOK")
[ -n "$backup_id" ] || fail "backup hook must return a durable backup identifier"
printf '%s\n' "release-auth: backup=$backup_id"

phase=migrate
"$AGENTNEXUS_RELEASE_MIGRATE_HOOK"

phase=start_new
"$AGENTNEXUS_RELEASE_START_NEW_HOOK"

phase=verify
if ! "$AGENTNEXUS_RELEASE_VERIFY_HOOK"; then
  fail "verification failed after phase=$phase; stop the new binary and restore backup $backup_id before restarting the old release"
fi

printf '%s\n' "release-auth: verified backup=$backup_id"
