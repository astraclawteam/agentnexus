package orgsource

func NewMockWeComProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "wecom", snapshot: snapshot}
}

func NewWeComHTTPProvider(config VendorHTTPConfig) Provider {
	return newVendorHTTPProvider("wecom", config)
}
