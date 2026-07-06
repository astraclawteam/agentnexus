package orgsource

func NewMockWeComProvider(snapshot Snapshot) Provider {
	return mockProvider{name: "wecom", snapshot: snapshot}
}
