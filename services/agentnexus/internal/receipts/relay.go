package receipts

import "time"

type Deliverer interface {
	Deliver(ReceiptRequest) error
}

type Relay struct {
	deliverer Deliverer
	now       func() time.Time
}

func NewRelay(deliverer Deliverer) *Relay {
	return &Relay{
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
	if r.deliverer != nil {
		if err := r.deliverer.Deliver(request); err != nil {
			return ReceiptRequest{}, err
		}
	}
	return request, nil
}
