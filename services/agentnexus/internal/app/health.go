package app

type HealthStatus struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Ready   bool   `json:"ready"`
}

func NewHealthStatus(service, version string, ready bool) HealthStatus {
	return HealthStatus{
		Service: service,
		Version: version,
		Ready:   ready,
	}
}
