package receipts

import "time"

type Deliverer interface {
	Deliver(ReceiptRequest) error
}

type DelivererFunc func(ReceiptRequest) error

func (fn DelivererFunc) Deliver(request ReceiptRequest) error {
	return fn(request)
}

type Relay struct {
	store     Store
	deliverer Deliverer
	now       func() time.Time
}

func NewRelay(deliverer Deliverer) *Relay {
	return NewRelayWithStore(NewMemoryStore(), deliverer)
}

func NewRelayWithStore(store Store, deliverer Deliverer) *Relay {
	if store == nil {
		store = NewMemoryStore()
	}
	return &Relay{
		store:     store,
		deliverer: deliverer,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (r *Relay) CreateAndDeliver(input RequestInput) (ReceiptRequest, error) {
	request := ReceiptRequest{
		ID:           input.ID,
		EnterpriseID: input.EnterpriseID,
		CaseTicketID: input.CaseTicketID,
		StepGrantID:  input.StepGrantID,
		Target:       input.Target,
		Status:       RequestStatusPending,
		CreatedAt:    r.now(),
	}
	request, err := r.store.CreateRequest(request)
	if err != nil {
		return ReceiptRequest{}, err
	}
	if r.deliverer != nil {
		if err := r.deliverer.Deliver(request); err != nil {
			return ReceiptRequest{}, err
		}
		request, err = r.store.UpdateRequestStatus(request.EnterpriseID, request.ID, RequestStatusDelivered)
		if err != nil {
			return ReceiptRequest{}, err
		}
	}
	return request, nil
}

func (r *Relay) ReceiveCallback(input CallbackInput) (Receipt, error) {
	request, err := r.store.GetRequest(input.EnterpriseID, input.RequestID)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		ID:        input.ReceiptID,
		RequestID: input.RequestID,
		Result:    input.Result,
		Evidence:  input.Evidence,
		CreatedAt: r.now(),
	}
	if err := VerifyReceipt(request, receipt); err != nil {
		return Receipt{}, err
	}
	receipt, err = r.store.CreateReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if _, err := r.store.UpdateRequestStatus(input.EnterpriseID, input.RequestID, statusForReceiptResult(input.Result)); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func statusForReceiptResult(result ReceiptResult) RequestStatus {
	switch result {
	case ReceiptApproved:
		return RequestStatusApproved
	case ReceiptDenied:
		return RequestStatusDenied
	case ReceiptNarrowed:
		return RequestStatusNarrowed
	case ReceiptInstructed:
		return RequestStatusInstructed
	default:
		return RequestStatusReceived
	}
}
