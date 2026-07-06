package orgsource

func NewMockDingTalkProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "dingtalk", snapshot: snapshot}
}

func NewDingTalkHTTPProvider(config VendorHTTPConfig) Provider {
	return newVendorHTTPProvider("dingtalk", config)
}
