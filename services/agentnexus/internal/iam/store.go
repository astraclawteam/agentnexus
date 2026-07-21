package iam

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("iam record not found")

const orgPublicationCleanupTimeout = 5 * time.Second

type Store interface {
	CreateEnterprise(context.Context, Enterprise) (Enterprise, error)
	UpsertEnterpriseUser(context.Context, EnterpriseUser) (EnterpriseUser, error)
	BindExternalIdentity(context.Context, ExternalIdentity) (ExternalIdentity, error)
	UpsertOrgUnit(context.Context, OrgUnit) (OrgUnit, error)
	AddOrgMembership(context.Context, OrgMembership) (OrgMembership, error)
	CreateOrgEvent(context.Context, OrgEvent) (OrgEvent, error)
	CreateOrgVersion(context.Context, OrgVersion) (OrgVersion, error)
	// PublishOrgVersion writes the event and the version it seals as ONE
	// transaction. It is a required capability, not an optional one: a store
	// that could only write them separately would be able to leave an event
	// with no version (invisible to the sealed feed) or a version with no
	// event. It was previously probed for with a type assertion and backed by
	// a non-atomic fallback that no store could ever reach.
	PublishOrgVersion(context.Context, OrgEvent, OrgVersion) (OrgVersion, error)
}

type memoryOrgPolicySnapshot struct {
	units       []OrgUnit
	memberships []OrgMembership
}

type MemoryStore struct {
	mu                 sync.Mutex
	enterprises        map[string]Enterprise
	users              map[string]EnterpriseUser
	identities         map[string]ExternalIdentity
	identityByExternal map[string]string
	orgUnits           map[string]OrgUnit
	memberships        map[string]OrgMembership
	orgEvents          map[string]OrgEvent
	orgVersions        map[string]OrgVersion
	policySnapshots    map[string]memoryOrgPolicySnapshot
	now                func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		enterprises:        map[string]Enterprise{},
		users:              map[string]EnterpriseUser{},
		identities:         map[string]ExternalIdentity{},
		identityByExternal: map[string]string{},
		orgUnits:           map[string]OrgUnit{},
		memberships:        map[string]OrgMembership{},
		orgEvents:          map[string]OrgEvent{},
		orgVersions:        map[string]OrgVersion{},
		policySnapshots:    map[string]memoryOrgPolicySnapshot{},
		now:                time.Now,
	}
}

func (s *MemoryStore) CreateEnterprise(_ context.Context, enterprise Enterprise) (Enterprise, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.enterprises[enterprise.ID]; ok {
		return existing, nil
	}
	enterprise.CreatedAt = s.now().UTC()
	s.enterprises[enterprise.ID] = enterprise
	return enterprise, nil
}

func (s *MemoryStore) UpsertEnterpriseUser(_ context.Context, user EnterpriseUser) (EnterpriseUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.users[key(user.EnterpriseID, user.ID)]; ok {
		user.CreatedAt = existing.CreatedAt
	} else {
		user.CreatedAt = s.now().UTC()
	}
	s.users[key(user.EnterpriseID, user.ID)] = user
	return user, nil
}

func (s *MemoryStore) BindExternalIdentity(_ context.Context, identity ExternalIdentity) (ExternalIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	externalKey := key(identity.EnterpriseID, identity.Provider+":"+identity.ExternalSubject)
	if existingID, ok := s.identityByExternal[externalKey]; ok {
		existing := s.identities[existingID]
		identity.ID = existing.ID
		identity.CreatedAt = existing.CreatedAt
	} else {
		identity.CreatedAt = s.now().UTC()
	}
	s.identities[identity.ID] = identity
	s.identityByExternal[externalKey] = identity.ID
	return identity, nil
}

func (s *MemoryStore) UpsertOrgUnit(_ context.Context, unit OrgUnit) (OrgUnit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.orgUnits[key(unit.EnterpriseID, unit.ID)]; ok {
		unit.CreatedAt = existing.CreatedAt
	} else {
		unit.CreatedAt = s.now().UTC()
	}
	s.orgUnits[key(unit.EnterpriseID, unit.ID)] = unit
	return unit, nil
}

func (s *MemoryStore) AddOrgMembership(_ context.Context, membership OrgMembership) (OrgMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	membership.CreatedAt = s.now().UTC()
	s.memberships[key(membership.EnterpriseID, membership.EnterpriseUserID+":"+membership.OrgUnitID+":"+string(membership.Role))] = membership
	return membership, nil
}

func (s *MemoryStore) CreateOrgEvent(_ context.Context, event OrgEvent) (OrgEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	event.CreatedAt = s.now().UTC()
	s.orgEvents[key(event.EnterpriseID, event.ID)] = event
	return event, nil
}

func (s *MemoryStore) CreateOrgVersion(ctx context.Context, version OrgVersion) (OrgVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return OrgVersion{}, err
	}
	if err := validateOrgVersion(version, false); err != nil {
		return OrgVersion{}, err
	}
	if err := s.validateNextOrgVersionLocked(version); err != nil {
		return OrgVersion{}, err
	}
	return s.createOrgVersionLocked(version), nil
}

func (s *MemoryStore) PublishOrgVersion(ctx context.Context, event OrgEvent, version OrgVersion) (OrgVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return OrgVersion{}, err
	}
	if err := validateOrgPublication(event, version); err != nil {
		return OrgVersion{}, err
	}
	if err := s.validateNextOrgVersionLocked(version); err != nil {
		return OrgVersion{}, err
	}
	if _, exists := s.orgEvents[key(event.EnterpriseID, event.ID)]; exists {
		return OrgVersion{}, errors.New("organization event already exists")
	}
	now := s.now().UTC()
	event.CreatedAt = now
	s.orgEvents[key(event.EnterpriseID, event.ID)] = event
	version.CreatedAt = now
	s.orgVersions[key(version.EnterpriseID, version.ID)] = version
	s.capturePolicySnapshotLocked(version)
	return version, nil
}

func (s *MemoryStore) createOrgVersionLocked(version OrgVersion) OrgVersion {
	version.CreatedAt = s.now().UTC()
	s.orgVersions[key(version.EnterpriseID, version.ID)] = version
	s.capturePolicySnapshotLocked(version)
	return version
}

func (s *MemoryStore) validateNextOrgVersionLocked(version OrgVersion) error {
	if _, exists := s.orgVersions[key(version.EnterpriseID, version.ID)]; exists {
		return errors.New("organization version already exists")
	}
	if _, exists := s.policySnapshots[memoryPolicySnapshotKey(version.EnterpriseID, version.VersionNumber)]; exists {
		return errors.New("organization policy snapshot already exists")
	}
	for _, existing := range s.orgVersions {
		if existing.EnterpriseID == version.EnterpriseID && existing.VersionNumber >= version.VersionNumber {
			return errors.New("organization version must strictly increase")
		}
	}
	return nil
}

func validateOrgPublication(event OrgEvent, version OrgVersion) error {
	if !canonicalNonEmpty(event.ID) || !canonicalNonEmpty(event.EnterpriseID) || !canonicalNonEmpty(event.EventType) {
		return errors.New("invalid organization event")
	}
	if err := validateOrgVersion(version, true); err != nil {
		return err
	}
	if event.EnterpriseID != version.EnterpriseID || version.SourceEventID != event.ID {
		return errors.New("organization publication event/version mismatch")
	}
	return nil
}

func validateOrgVersion(version OrgVersion, requireSourceEvent bool) error {
	if !canonicalNonEmpty(version.ID) || !canonicalNonEmpty(version.EnterpriseID) || version.VersionNumber <= 0 {
		return errors.New("invalid organization version")
	}
	if requireSourceEvent && !canonicalNonEmpty(version.SourceEventID) {
		return errors.New("invalid organization version source event")
	}
	if version.SourceEventID != "" && strings.TrimSpace(version.SourceEventID) != version.SourceEventID {
		return errors.New("invalid organization version source event")
	}
	return nil
}

func canonicalNonEmpty(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func (s *MemoryStore) capturePolicySnapshotLocked(version OrgVersion) {
	snapshot := memoryOrgPolicySnapshot{}
	for _, unit := range s.orgUnits {
		if unit.EnterpriseID == version.EnterpriseID {
			snapshot.units = append(snapshot.units, unit)
		}
	}
	for _, membership := range s.memberships {
		if membership.EnterpriseID == version.EnterpriseID {
			snapshot.memberships = append(snapshot.memberships, membership)
		}
	}
	sort.Slice(snapshot.units, func(i, j int) bool { return snapshot.units[i].ID < snapshot.units[j].ID })
	sort.Slice(snapshot.memberships, func(i, j int) bool {
		left, right := snapshot.memberships[i], snapshot.memberships[j]
		if left.EnterpriseUserID != right.EnterpriseUserID {
			return left.EnterpriseUserID < right.EnterpriseUserID
		}
		if left.OrgUnitID != right.OrgUnitID {
			return left.OrgUnitID < right.OrgUnitID
		}
		return left.Role < right.Role
	})
	s.policySnapshots[memoryPolicySnapshotKey(version.EnterpriseID, version.VersionNumber)] = snapshot
}

func (s *MemoryStore) policySnapshot(enterpriseID string, versionNumber int64) (memoryOrgPolicySnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, ok := s.policySnapshots[memoryPolicySnapshotKey(enterpriseID, versionNumber)]
	snapshot.units = append([]OrgUnit(nil), snapshot.units...)
	snapshot.memberships = append([]OrgMembership(nil), snapshot.memberships...)
	return snapshot, ok
}

func memoryPolicySnapshotKey(enterpriseID string, versionNumber int64) string {
	return key(enterpriseID, strconv.FormatInt(versionNumber, 10))
}

type PostgresStore struct {
	pool            postgresStoreDB
	publicationPool orgPublicationConnPool
}

type postgresStoreDB interface {
	db.DBTX
}

type orgPublicationConnPool interface {
	AcquireOrgPublicationConn(context.Context) (orgPublicationConn, error)
}

type orgPublicationConn interface {
	db.DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Release()
	Destroy(context.Context) error
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	if pool == nil {
		return &PostgresStore{}
	}
	return &PostgresStore{pool: pool, publicationPool: &pgxOrgPublicationPool{pool: pool}}
}

func newPostgresStoreWithDB(database postgresStoreDB) *PostgresStore {
	store := &PostgresStore{pool: database}
	if publicationPool, ok := database.(orgPublicationConnPool); ok {
		store.publicationPool = publicationPool
	}
	return store
}

type pgxOrgPublicationPool struct{ pool *pgxpool.Pool }

func (p *pgxOrgPublicationPool) AcquireOrgPublicationConn(ctx context.Context) (orgPublicationConn, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxOrgPublicationConn{Conn: conn}, nil
}

type pgxOrgPublicationConn struct{ *pgxpool.Conn }

func (c *pgxOrgPublicationConn) Destroy(ctx context.Context) error {
	return c.Hijack().Close(ctx)
}

// CreateEnterprise provisions (or renames) a tenant. The former atomic
// enterprise-approval-policy seeding is RETIRED with GA Task 0E: the
// enterprise risk policy existed only to feed the approval resolver, and
// AgentNexus no longer owns approval policy — the approval authority does.
func (s *PostgresStore) CreateEnterprise(ctx context.Context, enterprise Enterprise) (Enterprise, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO enterprises (id, name)
VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
RETURNING id, name, created_at`, enterprise.ID, enterprise.Name)
	return scanEnterprise(row)
}

func (s *PostgresStore) UpsertEnterpriseUser(ctx context.Context, user EnterpriseUser) (EnterpriseUser, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO enterprise_users (id, enterprise_id, display_name, email, phone)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE
SET display_name = EXCLUDED.display_name, email = EXCLUDED.email, phone = EXCLUDED.phone
RETURNING id, enterprise_id, display_name, email, phone, created_at`,
		user.ID, user.EnterpriseID, user.DisplayName, nullText(user.Email), nullText(user.Phone))
	return scanEnterpriseUser(row)
}

func (s *PostgresStore) BindExternalIdentity(ctx context.Context, identity ExternalIdentity) (ExternalIdentity, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO external_identities (id, enterprise_id, enterprise_user_id, provider, external_subject)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (enterprise_id, provider, external_subject) DO UPDATE
SET enterprise_user_id = EXCLUDED.enterprise_user_id
RETURNING id, enterprise_id, enterprise_user_id, provider, external_subject, created_at`,
		identity.ID, identity.EnterpriseID, identity.EnterpriseUserID, identity.Provider, identity.ExternalSubject)
	return scanExternalIdentity(row)
}

func (s *PostgresStore) UpsertOrgUnit(ctx context.Context, unit OrgUnit) (OrgUnit, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO org_units (id, enterprise_id, parent_id, name, unit_type)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE
SET parent_id = EXCLUDED.parent_id, name = EXCLUDED.name, unit_type = EXCLUDED.unit_type
RETURNING id, enterprise_id, parent_id, name, unit_type, created_at`,
		unit.ID, unit.EnterpriseID, nullText(unit.ParentID), unit.Name, unit.UnitType)
	return scanOrgUnit(row)
}

func (s *PostgresStore) AddOrgMembership(ctx context.Context, membership OrgMembership) (OrgMembership, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO org_memberships (enterprise_id, enterprise_user_id, org_unit_id, role)
VALUES ($1, $2, $3, $4)
ON CONFLICT (enterprise_id, enterprise_user_id, org_unit_id, role) DO UPDATE
SET role = EXCLUDED.role
RETURNING enterprise_id, enterprise_user_id, org_unit_id, role, created_at`,
		membership.EnterpriseID, membership.EnterpriseUserID, membership.OrgUnitID, membership.Role)
	return scanOrgMembership(row)
}

func (s *PostgresStore) CreateOrgEvent(ctx context.Context, event OrgEvent) (OrgEvent, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO org_events (id, enterprise_id, event_type, source_hash)
VALUES ($1, $2, $3, $4)
RETURNING id, enterprise_id, event_type, source_hash, created_at`,
		event.ID, event.EnterpriseID, event.EventType, nullText(event.SourceHash))
	return scanOrgEvent(row)
}

func (s *PostgresStore) CreateOrgVersion(ctx context.Context, version OrgVersion) (OrgVersion, error) {
	return s.publishOrgVersion(ctx, nil, version)
}

func (s *PostgresStore) PublishOrgVersion(ctx context.Context, event OrgEvent, version OrgVersion) (OrgVersion, error) {
	return s.publishOrgVersion(ctx, &event, version)
}

func (s *PostgresStore) publishOrgVersion(ctx context.Context, event *OrgEvent, version OrgVersion) (result OrgVersion, resultErr error) {
	if s == nil || s.pool == nil || s.publicationPool == nil {
		return OrgVersion{}, errors.New("iam store unavailable")
	}
	if err := ctx.Err(); err != nil {
		return OrgVersion{}, err
	}
	if event != nil {
		if err := validateOrgPublication(*event, version); err != nil {
			return OrgVersion{}, err
		}
	} else if err := validateOrgVersion(version, false); err != nil {
		return OrgVersion{}, err
	}
	conn, err := s.publicationPool.AcquireOrgPublicationConn(ctx)
	if err != nil {
		return OrgVersion{}, err
	}
	locked := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orgPublicationCleanupTimeout)
		defer cancel()
		if !locked {
			resultErr = errors.Join(resultErr, conn.Destroy(cleanupCtx))
			return
		}
		unlocked, unlockErr := releaseOrgPublicationSessionLock(cleanupCtx, conn, version.EnterpriseID)
		if unlockErr != nil || !unlocked {
			if unlockErr == nil {
				unlockErr = errors.New("organization publication session lock was not held")
			}
			resultErr = errors.Join(resultErr, unlockErr, conn.Destroy(cleanupCtx))
			return
		}
		conn.Release()
	}()
	if err := acquireOrgPublicationSessionLock(ctx, conn, version.EnterpriseID); err != nil {
		return OrgVersion{}, err
	}
	locked = true
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadWrite})
	if err != nil {
		return OrgVersion{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orgPublicationCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	queries := db.New(tx)
	if event != nil {
		if _, err := queries.CreateOrgEventForPolicyPublication(ctx, db.CreateOrgEventForPolicyPublicationParams{ID: event.ID, EnterpriseID: event.EnterpriseID, EventType: event.EventType, SourceHash: pgtype.Text{String: event.SourceHash, Valid: event.SourceHash != ""}}); err != nil {
			return OrgVersion{}, err
		}
	}
	record, err := queries.CreateOrgVersion(ctx, db.CreateOrgVersionParams{ID: version.ID, EnterpriseID: version.EnterpriseID, VersionNumber: version.VersionNumber, SourceEventID: pgtype.Text{String: version.SourceEventID, Valid: version.SourceEventID != ""}})
	if err != nil {
		return OrgVersion{}, err
	}
	params := db.CaptureOrgPolicySnapshotUnitsParams{EnterpriseID: version.EnterpriseID, VersionNumber: version.VersionNumber}
	if err := queries.CaptureOrgPolicySnapshotUnits(ctx, params); err != nil {
		return OrgVersion{}, err
	}
	if err := queries.CaptureOrgPolicySnapshotMemberships(ctx, db.CaptureOrgPolicySnapshotMembershipsParams(params)); err != nil {
		return OrgVersion{}, err
	}
	sealed, err := queries.SealOrgPolicySnapshot(ctx, db.SealOrgPolicySnapshotParams{EnterpriseID: version.EnterpriseID, VersionNumber: version.VersionNumber})
	if err != nil {
		return OrgVersion{}, err
	}
	if !sealed.PolicySnapshotSealed || sealed.ID != record.ID || sealed.EnterpriseID != record.EnterpriseID || sealed.VersionNumber != record.VersionNumber {
		return OrgVersion{}, errors.New("invalid sealed organization policy version")
	}
	if err := tx.Commit(ctx); err != nil {
		return OrgVersion{}, err
	}
	return OrgVersion{ID: sealed.ID, EnterpriseID: sealed.EnterpriseID, VersionNumber: sealed.VersionNumber, SourceEventID: textValue(sealed.SourceEventID), CreatedAt: sealed.CreatedAt.Time}, nil
}

func acquireOrgPublicationSessionLock(ctx context.Context, conn orgPublicationConn, enterpriseID string) error {
	var ignored any
	return conn.QueryRow(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, enterpriseID).Scan(&ignored)
}

func releaseOrgPublicationSessionLock(ctx context.Context, conn orgPublicationConn, enterpriseID string) (bool, error) {
	var unlocked bool
	err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, enterpriseID).Scan(&unlocked)
	return unlocked, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEnterprise(row rowScanner) (Enterprise, error) {
	var enterprise Enterprise
	if err := row.Scan(&enterprise.ID, &enterprise.Name, &enterprise.CreatedAt); err != nil {
		return Enterprise{}, mapNotFound(err)
	}
	return enterprise, nil
}

func scanEnterpriseUser(row rowScanner) (EnterpriseUser, error) {
	var user EnterpriseUser
	var email, phone pgtype.Text
	if err := row.Scan(&user.ID, &user.EnterpriseID, &user.DisplayName, &email, &phone, &user.CreatedAt); err != nil {
		return EnterpriseUser{}, mapNotFound(err)
	}
	user.Email = textValue(email)
	user.Phone = textValue(phone)
	return user, nil
}

func scanExternalIdentity(row rowScanner) (ExternalIdentity, error) {
	var identity ExternalIdentity
	if err := row.Scan(&identity.ID, &identity.EnterpriseID, &identity.EnterpriseUserID, &identity.Provider, &identity.ExternalSubject, &identity.CreatedAt); err != nil {
		return ExternalIdentity{}, mapNotFound(err)
	}
	return identity, nil
}

func scanOrgUnit(row rowScanner) (OrgUnit, error) {
	var unit OrgUnit
	var parentID pgtype.Text
	if err := row.Scan(&unit.ID, &unit.EnterpriseID, &parentID, &unit.Name, &unit.UnitType, &unit.CreatedAt); err != nil {
		return OrgUnit{}, mapNotFound(err)
	}
	unit.ParentID = textValue(parentID)
	return unit, nil
}

func scanOrgMembership(row rowScanner) (OrgMembership, error) {
	var membership OrgMembership
	if err := row.Scan(&membership.EnterpriseID, &membership.EnterpriseUserID, &membership.OrgUnitID, &membership.Role, &membership.CreatedAt); err != nil {
		return OrgMembership{}, mapNotFound(err)
	}
	return membership, nil
}

func scanOrgEvent(row rowScanner) (OrgEvent, error) {
	var event OrgEvent
	var sourceHash pgtype.Text
	if err := row.Scan(&event.ID, &event.EnterpriseID, &event.EventType, &sourceHash, &event.CreatedAt); err != nil {
		return OrgEvent{}, mapNotFound(err)
	}
	event.SourceHash = textValue(sourceHash)
	return event, nil
}

func scanOrgVersion(row rowScanner) (OrgVersion, error) {
	var version OrgVersion
	var sourceEventID pgtype.Text
	if err := row.Scan(&version.ID, &version.EnterpriseID, &version.VersionNumber, &sourceEventID, &version.CreatedAt); err != nil {
		return OrgVersion{}, mapNotFound(err)
	}
	version.SourceEventID = textValue(sourceEventID)
	return version, nil
}

func mapNotFound(err error) error {
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

func textValue(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func key(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}
