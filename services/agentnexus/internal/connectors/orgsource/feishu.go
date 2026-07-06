package orgsource

func NewMockFeishuProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "feishu", snapshot: snapshot}
}

func NewFeishuHTTPProvider(config VendorHTTPConfig) Provider {
	return newVendorHTTPProvider("feishu", config)
}
