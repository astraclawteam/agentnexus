package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("iam record not found")

type Store interface {
	CreateEnterprise(context.Context, Enterprise) (Enterprise, error)
	UpsertEnterpriseUser(context.Context, EnterpriseUser) (EnterpriseUser, error)
	BindExternalIdentity(context.Context, ExternalIdentity) (ExternalIdentity, error)
	UpsertOrgUnit(context.Context, OrgUnit) (OrgUnit, error)
	AddOrgMembership(context.Context, OrgMembership) (OrgMembership, error)
	CreateOrgEvent(context.Context, OrgEvent) (OrgEvent, error)
	CreateOrgVersion(context.Context, OrgVersion) (OrgVersion, error)
	GetOrgGraph(context.Context, string) (OrgGraph, error)
	NextOrgVersionNumber(context.Context, string) (int64, error)
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

func (s *MemoryStore) CreateOrgVersion(_ context.Context, version OrgVersion) (OrgVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	version.CreatedAt = s.now().UTC()
	s.orgVersions[key(version.EnterpriseID, version.ID)] = version
	return version, nil
}

func (s *MemoryStore) GetOrgGraph(_ context.Context, enterpriseID string) (OrgGraph, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	graph := OrgGraph{}
	for _, user := range s.users {
		if user.EnterpriseID == enterpriseID {
			graph.Users = append(graph.Users, user)
		}
	}
	for _, identity := range s.identities {
		if identity.EnterpriseID == enterpriseID {
			graph.ExternalIdentities = append(graph.ExternalIdentities, identity)
		}
	}
	for _, unit := range s.orgUnits {
		if unit.EnterpriseID == enterpriseID {
			graph.Departments = append(graph.Departments, unit)
		}
	}
	for _, membership := range s.memberships {
		if membership.EnterpriseID == enterpriseID {
			graph.Memberships = append(graph.Memberships, membership)
		}
	}
	for _, version := range s.orgVersions {
		if version.EnterpriseID == enterpriseID {
			graph.Versions = append(graph.Versions, version)
		}
	}
	sortOrgGraph(&graph)
	return graph, nil
}

func (s *MemoryStore) NextOrgVersionNumber(_ context.Context, enterpriseID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var maxVersion int64
	for _, version := range s.orgVersions {
		if version.EnterpriseID == enterpriseID && version.VersionNumber > maxVersion {
			maxVersion = version.VersionNumber
		}
	}
	return maxVersion + 1, nil
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

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
	row := s.pool.QueryRow(ctx, `
INSERT INTO org_versions (id, enterprise_id, version_number, source_event_id)
VALUES ($1, $2, $3, $4)
RETURNING id, enterprise_id, version_number, source_event_id, created_at`,
		version.ID, version.EnterpriseID, version.VersionNumber, nullText(version.SourceEventID))
	return scanOrgVersion(row)
}

func (s *PostgresStore) GetOrgGraph(ctx context.Context, enterpriseID string) (OrgGraph, error) {
	var graph OrgGraph

	userRows, err := s.pool.Query(ctx, `
SELECT id, enterprise_id, display_name, email, phone, created_at
FROM enterprise_users
WHERE enterprise_id = $1
ORDER BY id`, enterpriseID)
	if err != nil {
		return OrgGraph{}, err
	}
	defer userRows.Close()
	for userRows.Next() {
		user, err := scanEnterpriseUser(userRows)
		if err != nil {
			return OrgGraph{}, err
		}
		graph.Users = append(graph.Users, user)
	}
	if err := userRows.Err(); err != nil {
		return OrgGraph{}, err
	}

	identityRows, err := s.pool.Query(ctx, `
SELECT id, enterprise_id, enterprise_user_id, provider, external_subject, created_at
FROM external_identities
WHERE enterprise_id = $1
ORDER BY provider, external_subject`, enterpriseID)
	if err != nil {
		return OrgGraph{}, err
	}
	defer identityRows.Close()
	for identityRows.Next() {
		identity, err := scanExternalIdentity(identityRows)
		if err != nil {
			return OrgGraph{}, err
		}
		graph.ExternalIdentities = append(graph.ExternalIdentities, identity)
	}
	if err := identityRows.Err(); err != nil {
		return OrgGraph{}, err
	}

	unitRows, err := s.pool.Query(ctx, `
SELECT id, enterprise_id, parent_id, name, unit_type, created_at
FROM org_units
WHERE enterprise_id = $1
ORDER BY id`, enterpriseID)
	if err != nil {
		return OrgGraph{}, err
	}
	defer unitRows.Close()
	for unitRows.Next() {
		unit, err := scanOrgUnit(unitRows)
		if err != nil {
			return OrgGraph{}, err
		}
		graph.Departments = append(graph.Departments, unit)
	}
	if err := unitRows.Err(); err != nil {
		return OrgGraph{}, err
	}

	membershipRows, err := s.pool.Query(ctx, `
SELECT enterprise_id, enterprise_user_id, org_unit_id, role, created_at
FROM org_memberships
WHERE enterprise_id = $1
ORDER BY enterprise_user_id, org_unit_id, role`, enterpriseID)
	if err != nil {
		return OrgGraph{}, err
	}
	defer membershipRows.Close()
	for membershipRows.Next() {
		membership, err := scanOrgMembership(membershipRows)
		if err != nil {
			return OrgGraph{}, err
		}
		graph.Memberships = append(graph.Memberships, membership)
	}
	if err := membershipRows.Err(); err != nil {
		return OrgGraph{}, err
	}

	versionRows, err := s.pool.Query(ctx, `
SELECT id, enterprise_id, version_number, source_event_id, created_at
FROM org_versions
WHERE enterprise_id = $1
ORDER BY version_number`, enterpriseID)
	if err != nil {
		return OrgGraph{}, err
	}
	defer versionRows.Close()
	for versionRows.Next() {
		version, err := scanOrgVersion(versionRows)
		if err != nil {
			return OrgGraph{}, err
		}
		graph.Versions = append(graph.Versions, version)
	}
	if err := versionRows.Err(); err != nil {
		return OrgGraph{}, err
	}
	return graph, nil
}

func (s *PostgresStore) NextOrgVersionNumber(ctx context.Context, enterpriseID string) (int64, error) {
	var next int64
	if err := s.pool.QueryRow(ctx, `
SELECT COALESCE(MAX(version_number), 0) + 1
FROM org_versions
WHERE enterprise_id = $1`, enterpriseID).Scan(&next); err != nil {
		return 0, err
	}
	return next, nil
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

func randomID(prefix string) string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return prefix + "_" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return prefix + "_" + hex.EncodeToString(bytes[:])
}

func sortOrgGraph(graph *OrgGraph) {
	sort.Slice(graph.Users, func(i, j int) bool { return graph.Users[i].ID < graph.Users[j].ID })
	sort.Slice(graph.ExternalIdentities, func(i, j int) bool {
		if graph.ExternalIdentities[i].Provider == graph.ExternalIdentities[j].Provider {
			return graph.ExternalIdentities[i].ExternalSubject < graph.ExternalIdentities[j].ExternalSubject
		}
		return graph.ExternalIdentities[i].Provider < graph.ExternalIdentities[j].Provider
	})
	sort.Slice(graph.Departments, func(i, j int) bool { return graph.Departments[i].ID < graph.Departments[j].ID })
	sort.Slice(graph.Memberships, func(i, j int) bool {
		if graph.Memberships[i].EnterpriseUserID == graph.Memberships[j].EnterpriseUserID {
			return graph.Memberships[i].OrgUnitID < graph.Memberships[j].OrgUnitID
		}
		return graph.Memberships[i].EnterpriseUserID < graph.Memberships[j].EnterpriseUserID
	})
	sort.Slice(graph.Versions, func(i, j int) bool { return graph.Versions[i].VersionNumber < graph.Versions[j].VersionNumber })
}
