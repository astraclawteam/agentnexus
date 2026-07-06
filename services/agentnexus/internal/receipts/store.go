package receipts

import (
	"fmt"
	"sync"
)

type Store interface {
	CreateRequest(ReceiptRequest) (ReceiptRequest, error)
	GetRequest(string, string) (ReceiptRequest, error)
	UpdateRequestStatus(string, string, RequestStatus) (ReceiptRequest, error)
	CreateReceipt(Receipt) (Receipt, error)
}

type MemoryStore struct {
	mu       sync.Mutex
	requests map[string]ReceiptRequest
	receipts map[string]Receipt
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		requests: map[string]ReceiptRequest{},
		receipts: map[string]Receipt{},
	}
}

func (s *MemoryStore) CreateRequest(request ReceiptRequest) (ReceiptRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests[requestKey(request.EnterpriseID, request.ID)] = request
	return request, nil
}

func (s *MemoryStore) GetRequest(enterpriseID, id string) (ReceiptRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, ok := s.requests[requestKey(enterpriseID, id)]
	if !ok {
		return ReceiptRequest{}, fmt.Errorf("receipt request not found")
	}
	return request, nil
}

func (s *MemoryStore) UpdateRequestStatus(enterpriseID, id string, status RequestStatus) (ReceiptRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := requestKey(enterpriseID, id)
	request, ok := s.requests[key]
	if !ok {
		return ReceiptRequest{}, fmt.Errorf("receipt request not found")
	}
	request.Status = status
	s.requests[key] = request
	return request, nil
}

func (s *MemoryStore) CreateReceipt(receipt Receipt) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.receipts[receipt.ID] = receipt
	return receipt, nil
}

func requestKey(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}

var _ Store = (*MemoryStore)(nil)
