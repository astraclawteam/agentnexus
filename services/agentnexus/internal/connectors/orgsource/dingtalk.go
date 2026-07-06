package orgsource

func NewMockDingTalkProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "dingtalk", snapshot: snapshot}
}
