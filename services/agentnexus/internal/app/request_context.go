package app

import "errors"

type RequestContext struct {
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
}

func ParseRequestContext(values map[string]string) (RequestContext, error) {
	ctx := RequestContext{
		EnterpriseID: values["enterprise_id"],
		ActorUserID:  values["actor_user_id"],
		RequestID:    values["request_id"],
		TraceID:      values["trace_id"],
	}

	if ctx.EnterpriseID == "" {
		return RequestContext{}, errors.New("enterprise_id is required")
	}
	if ctx.ActorUserID == "" {
		return RequestContext{}, errors.New("actor_user_id is required")
	}
	if ctx.RequestID == "" {
		return RequestContext{}, errors.New("request_id is required")
	}

	return ctx, nil
}
