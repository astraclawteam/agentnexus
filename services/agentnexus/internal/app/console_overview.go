package app

type ConsoleOverview struct {
	Source        ConsoleOverviewSource `json:"source"`
	Title         string                `json:"title"`
	Subtitle      string                `json:"subtitle"`
	Enterprise    string                `json:"enterprise"`
	EnterpriseAlt string                `json:"enterpriseAlt"`
	PrivateEnv    string                `json:"privateEnv"`
	Topbar        ConsoleTopbar         `json:"topbar"`
	Pulse         ConsolePulse          `json:"pulse"`
	Metrics       [][]string            `json:"metrics"`
	ResourceMap   ConsoleResourceMap    `json:"resourceMap"`
	Tickets       ConsoleTickets        `json:"tickets"`
	Connectors    ConsoleConnectors     `json:"connectors"`
	Agent         ConsoleAgent          `json:"agent"`
}

type ConsoleOverviewSource struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Detail    string `json:"detail"`
	UpdatedAt string `json:"updatedAt"`
}

type ConsoleTopbar struct {
	EnterpriseLabel string `json:"enterpriseLabel"`
	Search          string `json:"search"`
	Sync            string `json:"sync"`
	Notifications   string `json:"notifications"`
	Avatar          string `json:"avatar"`
	ExportAudit     string `json:"exportAudit"`
}

type ConsolePulse struct {
	BrandName         string     `json:"brandName"`
	BrandSub          string     `json:"brandSub"`
	CurrentEnterprise string     `json:"currentEnterprise"`
	OrgSnapshot       string     `json:"orgSnapshot"`
	TodayPulse        string     `json:"todayPulse"`
	PendingSignals    string     `json:"pendingSignals"`
	RecentEvents      string     `json:"recentEvents"`
	StatusOnline      string     `json:"statusOnline"`
	PolicyPending     string     `json:"policyPending"`
	OrgVersion        string     `json:"orgVersion"`
	Stats             [][]string `json:"stats"`
	PulseStats        [][]string `json:"pulseStats"`
	Signals           [][]string `json:"signals"`
	Events            []string   `json:"events"`
}

type ConsoleResourceMap struct {
	Title string              `json:"title"`
	Desc  string              `json:"desc"`
	Tabs  []string            `json:"tabs"`
	Aria  string              `json:"aria"`
	Nodes map[string][]string `json:"nodes"`
}

type ConsoleTickets struct {
	Title   string     `json:"title"`
	Desc    string     `json:"desc"`
	Filter  string     `json:"filter"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

type ConsoleConnectors struct {
	Title string     `json:"title"`
	Desc  string     `json:"desc"`
	Smoke string     `json:"smoke"`
	Rows  [][]string `json:"rows"`
}

type ConsoleAgent struct {
	Open       string   `json:"open"`
	Title      string   `json:"title"`
	Desc       string   `json:"desc"`
	Close      string   `json:"close"`
	Intro      string   `json:"intro"`
	Prompts    []string `json:"prompts"`
	Input      string   `json:"input"`
	Send       string   `json:"send"`
	SentPrefix string   `json:"sentPrefix"`
}

func NewConsoleOverview(locale string) ConsoleOverview {
	if locale == "zh" {
		return zhConsoleOverview()
	}
	return enConsoleOverview()
}

func zhConsoleOverview() ConsoleOverview {
	return ConsoleOverview{
		Source: ConsoleOverviewSource{
			Kind:      "api",
			Label:     "Gateway API",
			Detail:    "gateway-api 返回的 open-core 开发总览数据，不包含真实客户数据。",
			UpdatedAt: "2026-07-06T00:00:00+08:00",
		},
		Title:         "企业智能行政中枢",
		Subtitle:      "懂组织、懂系统、懂权限、懂审批，负责让所有 Agent 安全地在企业里办事。",
		Enterprise:    "示例企业（Gateway API）",
		EnterpriseAlt: "示例研发中心",
		PrivateEnv:    "open-core 开发视图 · Gateway API",
		Topbar: ConsoleTopbar{
			EnterpriseLabel: "企业",
			Search:          "搜索员工、系统、策略、审计号",
			Sync:            "同步组织",
			Notifications:   "通知",
			Avatar:          "测",
			ExportAudit:     "导出审计",
		},
		Pulse: ConsolePulse{
			BrandName:         "企业网关",
			BrandSub:          "Agent Admin",
			CurrentEnterprise: "当前企业",
			OrgSnapshot:       "组织快照",
			TodayPulse:        "今日企业脉搏",
			PendingSignals:    "待处理信号",
			RecentEvents:      "最近组织事件",
			StatusOnline:      "gateway-api 在线",
			PolicyPending:     "2 个策略待发布",
			OrgVersion:        "Gateway API 2026.07.06",
			Stats: [][]string{
				{"员工", "1,284"},
				{"部门", "86"},
				{"项目组", "42"},
			},
			PulseStats: [][]string{
				{"3", "新入职"},
				{"2", "组织变更"},
				{"1", "项目组新增"},
				{"42/42", "知识空间"},
			},
			Signals: [][]string{
				{"external_receipt", "审批回执待返回", "16", "warn"},
				{"connector_attention", "连接器需关注", "2", "warn"},
				{"risk_blocked", "高风险读取已拦截", "4", "ok"},
				{"org_schema_changed", "组织源字段变更", "1", "info"},
			},
			Events: []string{"示例员工 A 加入研发一部", "MES 项目组新增成员", "财务主管关系已同步", "项目组空间已自动创建"},
		},
		Metrics: [][]string{
			{"已同步员工", "1,284", "示例组织源 98.4% 匹配", "good"},
			{"已连接系统", "27", "9 个目标实例", "neutral"},
			{"待审批请求", "16", "4 个高风险读取", "warn"},
			{"今日 Agent 访问", "3,642", "拒绝 73 次越权", "good"},
		},
		ResourceMap: ConsoleResourceMap{
			Title: "企业资源地图",
			Desc:  "组织、知识库与业务系统的实时连接关系",
			Tabs:  []string{"组织", "系统", "风险"},
			Aria:  "企业资源地图",
			Nodes: map[string][]string{
				"core":      {"Enterprise IAM", "组织图 · 员工 · 项目组"},
				"source":    {"示例组织源", "1,284 员工"},
				"knowledge": {"知识库 AgentRag", "42 组织空间"},
				"finance":   {"金融财务", "高风险 · 需审批"},
				"mes":       {"MES 生产", "只读视图"},
				"file":      {"文件系统", "证据原文"},
				"receipt":   {"回执通道", "16 待回执"},
			},
		},
		Tickets: ConsoleTickets{
			Title:   "最近 Access Tickets",
			Desc:    "任务级授权、审批与数据源访问轨迹",
			Filter:  "过滤",
			Columns: []string{"Ticket", "员工", "意图", "资源", "决策"},
			Rows: [][]string{
				{"CT-API-0918", "示例员工 A", "我的工作内容是什么", "知识库 + OA", "已授权", "allow"},
				{"CT-API-0886", "示例员工 B", "读取财务本月费用", "金融财务", "待回执", "review"},
				{"CT-API-0832", "示例员工 C", "查看 MES 异常工单", "MES 生产", "已授权", "allow"},
				{"CT-API-0799", "示例员工 D", "导出供应商税号", "金融财务", "已拒绝", "deny"},
				{"CT-API-0741", "示例员工 E", "汇总项目组周报", "文件系统", "已授权", "allow"},
			},
		},
		Connectors: ConsoleConnectors{
			Title: "连接器健康",
			Desc:  "目标实例、凭证、同步和测试状态",
			Smoke: "Smoke",
			Rows: [][]string{
				{"示例组织源", "通讯录 1,284 人 · 部门 86 个", "正常", "ok"},
				{"文件系统", "简报原文与证据 · 12.4TB", "正常", "ok"},
				{"金融 K3Cloud", "凭证读取需审批 · 2 个字段脱敏", "需关注", "warn"},
				{"MES 工单只读", "数据库视图 · smoke 通过", "正常", "ok"},
				{"审批回执通道", "待回执 16 · IM 同步开启", "需关注", "warn"},
			},
		},
		Agent: ConsoleAgent{
			Open:       "打开 Agent 对话",
			Title:      "网关 Agent",
			Desc:       "描述你想接入、调整或排查的事情",
			Close:      "关闭",
			Intro:      "我可以帮你创建系统插件、根据接口资料生成配置草稿、排查同步失败，或解释某个 Access Ticket 的链路。",
			Prompts:    []string{"生成 MES 插件", "评估字段变更", "解释 Ticket"},
			Input:      "输入需求，例如：帮我接入新的 OA 回执接口",
			Send:       "发送",
			SentPrefix: "已记录需求",
		},
	}
}

func enConsoleOverview() ConsoleOverview {
	return ConsoleOverview{
		Source: ConsoleOverviewSource{
			Kind:      "api",
			Label:     "Gateway API",
			Detail:    "gateway-api returned open-core development overview data without customer data.",
			UpdatedAt: "2026-07-06T00:00:00+08:00",
		},
		Title:         "Enterprise Agent Command Center",
		Subtitle:      "Knows orgs, systems, permissions, and approvals so every Agent can work safely inside the enterprise.",
		Enterprise:    "Example Enterprise (Gateway API)",
		EnterpriseAlt: "Example R&D Center",
		PrivateEnv:    "Open-core development view · Gateway API",
		Topbar: ConsoleTopbar{
			EnterpriseLabel: "Enterprise",
			Search:          "Search employees, systems, policies, audit IDs",
			Sync:            "Sync org",
			Notifications:   "Notifications",
			Avatar:          "QA",
			ExportAudit:     "Export audit",
		},
		Pulse: ConsolePulse{
			BrandName:         "Enterprise Gateway",
			BrandSub:          "Agent Admin",
			CurrentEnterprise: "Current enterprise",
			OrgSnapshot:       "Org snapshot",
			TodayPulse:        "Enterprise pulse",
			PendingSignals:    "Pending signals",
			RecentEvents:      "Recent org events",
			StatusOnline:      "gateway-api online",
			PolicyPending:     "2 policies pending release",
			OrgVersion:        "Gateway API 2026.07.06",
			Stats: [][]string{
				{"Employees", "1,284"},
				{"Departments", "86"},
				{"Project teams", "42"},
			},
			PulseStats: [][]string{
				{"3", "New hires"},
				{"2", "Org changes"},
				{"1", "New team"},
				{"42/42", "Knowledge spaces"},
			},
			Signals: [][]string{
				{"external_receipt", "Approval receipts pending", "16", "warn"},
				{"connector_attention", "Connectors need attention", "2", "warn"},
				{"risk_blocked", "High-risk reads blocked", "4", "ok"},
				{"org_schema_changed", "Org source field changed", "1", "info"},
			},
			Events: []string{"Example employee A joined R&D I", "MES team added a member", "Finance manager line synced", "Project space auto-created"},
		},
		Metrics: [][]string{
			{"Synced employees", "1,284", "Example org source 98.4% matched", "good"},
			{"Connected systems", "27", "9 target instances", "neutral"},
			{"Pending approvals", "16", "4 high-risk reads", "warn"},
			{"Agent visits today", "3,642", "73 overreach attempts denied", "good"},
		},
		ResourceMap: ConsoleResourceMap{
			Title: "Enterprise Resource Map",
			Desc:  "Live relationships between orgs, knowledge spaces, and business systems",
			Tabs:  []string{"Org", "Systems", "Risk"},
			Aria:  "Enterprise resource map",
			Nodes: map[string][]string{
				"core":      {"Enterprise IAM", "Org graph · employees · teams"},
				"source":    {"Example org source", "1,284 employees"},
				"knowledge": {"Knowledge AgentRag", "42 org spaces"},
				"finance":   {"Kingdee finance", "High risk · approval"},
				"mes":       {"MES system", "Read-only view"},
				"file":      {"File system", "Original evidence"},
				"receipt":   {"Receipt relay", "16 pending"},
			},
		},
		Tickets: ConsoleTickets{
			Title:   "Recent Access Tickets",
			Desc:    "Task grants, approvals, and data-source access trails",
			Filter:  "Filter",
			Columns: []string{"Ticket", "Employee", "Intent", "Resource", "Decision"},
			Rows: [][]string{
				{"CT-API-0918", "Example employee A", "What should I work on?", "Knowledge + OA", "Granted", "allow"},
				{"CT-API-0886", "Example employee B", "Read finance expenses", "Kingdee", "Waiting", "review"},
				{"CT-API-0832", "Example employee C", "View MES exceptions", "MES", "Granted", "allow"},
				{"CT-API-0799", "Example employee D", "Export supplier tax IDs", "Kingdee", "Denied", "deny"},
				{"CT-API-0741", "Example employee E", "Summarize team weekly", "File system", "Granted", "allow"},
			},
		},
		Connectors: ConsoleConnectors{
			Title: "Connector Health",
			Desc:  "Target instances, credentials, sync, and smoke status",
			Smoke: "Smoke",
			Rows: [][]string{
				{"Example org source", "Contacts 1,284 · departments 86", "Normal", "ok"},
				{"File system", "Brief originals and evidence · 12.4TB", "Normal", "ok"},
				{"Kingdee K3Cloud", "Voucher reads need approval · 2 masked fields", "Attention", "warn"},
				{"MES read-only orders", "Database view · smoke passed", "Normal", "ok"},
				{"Approval receipt relay", "16 pending · IM sync enabled", "Attention", "warn"},
			},
		},
		Agent: ConsoleAgent{
			Open:       "Open Agent chat",
			Title:      "Gateway Agent",
			Desc:       "Describe the integration, change, or issue you want to handle",
			Close:      "Close",
			Intro:      "I can create connector drafts, generate instance configs from interface docs, diagnose sync failures, or explain an Access Ticket chain.",
			Prompts:    []string{"Generate MES connector", "Assess field change", "Explain Ticket"},
			Input:      "Type a request, for example: connect a new OA receipt API",
			Send:       "Send",
			SentPrefix: "Request captured",
		},
	}
}
