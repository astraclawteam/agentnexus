package instance

import (
	"context"
	"fmt"
	"sync"
)

type MemoryStore struct {
	mu           sync.Mutex
	packages     map[string]Package
	instances    map[string]Config
	healthEvents []HealthEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		packages:  map[string]Package{},
		instances: map[string]Config{},
	}
}

func (s *MemoryStore) CreatePackage(_ context.Context, pkg Package) (Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.packages[pkg.ID] = pkg
	return pkg, nil
}

func (s *MemoryStore) CreateInstance(_ context.Context, instance Config) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.instances[instanceKey(instance.EnterpriseID, instance.ID)] = instance
	return instance, nil
}

func (s *MemoryStore) CreateHealthEvent(_ context.Context, event HealthEvent) (HealthEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.healthEvents = append(s.healthEvents, event)
	return event, nil
}

func (s *MemoryStore) GetPackage(_ context.Context, id string) (Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkg, ok := s.packages[id]
	if !ok {
		return Package{}, fmt.Errorf("connector package not found")
	}
	return pkg, nil
}

func (s *MemoryStore) GetInstance(_ context.Context, enterpriseID, id string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance, ok := s.instances[instanceKey(enterpriseID, id)]
	if !ok {
		return Config{}, fmt.Errorf("connector instance not found")
	}
	return instance, nil
}

func (s *MemoryStore) UpdateInstanceStatus(_ context.Context, enterpriseID, id, status string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := instanceKey(enterpriseID, id)
	instance, ok := s.instances[key]
	if !ok {
		return Config{}, fmt.Errorf("connector instance not found")
	}
	instance.Status = status
	s.instances[key] = instance
	return instance, nil
}

func instanceKey(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}

func (s *MemoryStore) HealthEvents() []HealthEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]HealthEvent(nil), s.healthEvents...)
}

type MemoryAuditSink struct {
	mu     sync.Mutex
	events []ConnectorAuditEvent
}

func NewMemoryAuditSink() *MemoryAuditSink {
	return &MemoryAuditSink{}
}

func (s *MemoryAuditSink) AppendConnectorAudit(_ context.Context, event ConnectorAuditEvent) (ConnectorAuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	return event, nil
}

func (s *MemoryAuditSink) Events() []ConnectorAuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]ConnectorAuditEvent(nil), s.events...)
}
