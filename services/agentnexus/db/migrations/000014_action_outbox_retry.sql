-- 000014_action_outbox_retry.sql
--
-- Retry accounting for the transactional outbox (GA Task 0F follow-up).
--
-- 000010 gave action_outbox an `attempts` column that only ever moved on the
-- SUCCESS statement, so it counted publishes rather than attempts and nothing
-- could read a retry history off it. Worse, the drain had no way to record a
-- FAILED attempt at all: guard_action_outbox permitted exactly one update
-- shape (published false->true), so a failing row was indistinguishable from a
-- never-tried one and the oldest-first drain retried it forever on every tick,
-- ahead of every later intent.
--
-- This migration adds the three facts a bounded retry needs and widens the
-- guard by exactly one more legal update shape:
--
--   next_attempt_at   when a failed row becomes eligible again (NULL = now).
--   last_error        the coded reason of the last failed attempt.
--   dead_lettered_at  the give-up stamp: the drain stops claiming the row and
--                     an operator owns it. A dead-lettered row is never
--                     published, so no side effect is silently dropped — the
--                     durable intent stays queryable evidence.
--
-- The outbox stays append-only in every other respect: the binding columns
-- (tenant, dispatch, action, capability, parameter hash, grant, kind,
-- created_at) remain immutable, DELETE and TRUNCATE remain rejected, and a row
-- is still published at most once.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE action_outbox
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN dead_lettered_at TIMESTAMPTZ;

-- Giving up and delivering are mutually exclusive outcomes of the same row.
ALTER TABLE action_outbox
    ADD CONSTRAINT action_outbox_dead_letter_never_published
    CHECK (dead_lettered_at IS NULL OR published = false);

-- The drain reads eligible rows only, so the pending index must not carry the
-- rows it has given up on.
DROP INDEX IF EXISTS idx_action_outbox_pending;
CREATE INDEX idx_action_outbox_pending ON action_outbox(tenant_ref, created_at)
    WHERE published = false AND dead_lettered_at IS NULL;

-- guard_action_outbox now permits exactly TWO legal updates, with the binding
-- columns unchanged in both:
--
--   1. the publish stamp: published false->true with published_at set, on a row
--      that was not given up on;
--   2. one FAILED attempt: published stays false, attempts rises by exactly
--      one, and the row may record its backoff, its coded reason and — when the
--      caller gives up — its dead-letter stamp.
--
-- Everything else (a second publish, a publish of a dead-lettered row, an
-- attempts rewrite, resurrecting a dead-lettered row, a binding mutation, a
-- delete) is still rejected.
CREATE OR REPLACE FUNCTION guard_action_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    binding_unchanged BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the action outbox is append-only';
    END IF;
    binding_unchanged :=
        ROW(NEW.tenant_ref, NEW.dispatch_ref, NEW.action_ref, NEW.capability, NEW.parameter_hash, NEW.grant_ref, NEW.kind, NEW.created_at)
        IS NOT DISTINCT FROM
        ROW(OLD.tenant_ref, OLD.dispatch_ref, OLD.action_ref, OLD.capability, OLD.parameter_hash, OLD.grant_ref, OLD.kind, OLD.created_at);
    IF NOT binding_unchanged THEN
        RAISE EXCEPTION 'the action outbox dispatch binding is immutable';
    END IF;
    IF OLD.published = true OR OLD.dead_lettered_at IS NOT NULL THEN
        RAISE EXCEPTION 'the action outbox is append-only; a published or dead-lettered row is final';
    END IF;
    -- 1. the publish stamp.
    IF NEW.published = true AND NEW.published_at IS NOT NULL AND
       NEW.dead_lettered_at IS NULL AND NEW.attempts >= OLD.attempts THEN
        RETURN NEW;
    END IF;
    -- 2. one failed attempt (optionally the final one).
    IF NEW.published = false AND NEW.published_at IS NULL AND
       NEW.attempts = OLD.attempts + 1 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'the action outbox records one publish or one failed attempt per update';
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_action_outbox_pending;
CREATE INDEX idx_action_outbox_pending ON action_outbox(tenant_ref, created_at)
    WHERE published = false;

ALTER TABLE action_outbox
    DROP CONSTRAINT IF EXISTS action_outbox_dead_letter_never_published;

ALTER TABLE action_outbox
    DROP COLUMN IF EXISTS next_attempt_at,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS dead_lettered_at;

CREATE OR REPLACE FUNCTION guard_action_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the action outbox is append-only';
    END IF;
    IF OLD.published = false AND NEW.published = true AND NEW.attempts >= OLD.attempts AND
       ROW(NEW.tenant_ref, NEW.dispatch_ref, NEW.action_ref, NEW.capability, NEW.parameter_hash, NEW.grant_ref, NEW.kind, NEW.created_at)
       IS NOT DISTINCT FROM
       ROW(OLD.tenant_ref, OLD.dispatch_ref, OLD.action_ref, OLD.capability, OLD.parameter_hash, OLD.grant_ref, OLD.kind, OLD.created_at)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'the action outbox is append-only; a row is published exactly once';
END;
$$;
-- +goose StatementEnd
