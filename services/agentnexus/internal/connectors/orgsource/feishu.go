package orgsource

func NewMockFeishuProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "feishu", snapshot: snapshot}
}
