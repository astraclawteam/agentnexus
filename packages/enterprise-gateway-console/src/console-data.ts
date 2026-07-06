export type Locale = "zh" | "en";

export type ConsoleOverview = {
  source: {
    kind: "api" | "development_fixture";
    label: string;
    detail: string;
    updatedAt: string;
  };
  title: string;
  subtitle: string;
  enterprise: string;
  enterpriseAlt: string;
  privateEnv: string;
  topbar: {
    enterpriseLabel: string;
    search: string;
    sync: string;
    notifications: string;
    avatar: string;
    exportAudit: string;
  };
  pulse: {
    brandName: string;
    brandSub: string;
    currentEnterprise: string;
    orgSnapshot: string;
    todayPulse: string;
    pendingSignals: string;
    recentEvents: string;
    statusOnline: string;
    policyPending: string;
    orgVersion: string;
    stats: string[][];
    pulseStats: string[][];
    signals: string[][];
    events: string[];
  };
  metrics: string[][];
  resourceMap: {
    title: string;
    desc: string;
    tabs: string[];
    aria: string;
    nodes: Record<string, string[]>;
  };
  tickets: {
    title: string;
    desc: string;
    filter: string;
    columns: string[];
    rows: string[][];
  };
  connectors: {
    title: string;
    desc: string;
    smoke: string;
    rows: string[][];
  };
  agent: {
    open: string;
    title: string;
    desc: string;
    close: string;
    intro: string;
    prompts: string[];
    input: string;
    send: string;
    sentPrefix: string;
  };
};

export const localeNames: Record<Locale, string> = {
  zh: "中文",
  en: "EN"
};

export const developmentFixtures: Record<Locale, ConsoleOverview> = {
  zh: {
    source: {
      kind: "development_fixture",
      label: "本地开发数据",
      detail: "未连接 Gateway API，当前仅展示本地开发 fixture，不代表生产企业数据。",
      updatedAt: "2026-07-06T00:00:00+08:00"
    },
    title: "企业智能行政中枢",
    subtitle: "懂组织、懂系统、懂权限、懂审批，负责让所有 Agent 安全地在企业里办事。",
    enterprise: "示例企业（本地开发）",
    enterpriseAlt: "示例研发中心",
    privateEnv: "本地开发视图 · 未连接 Gateway API",
    topbar: {
      enterpriseLabel: "企业",
      search: "搜索员工、系统、策略、审计号",
      sync: "同步组织",
      notifications: "通知",
      avatar: "测",
      exportAudit: "导出审计"
    },
    pulse: {
      brandName: "企业网关",
      brandSub: "Agent Admin",
      currentEnterprise: "当前企业",
      orgSnapshot: "组织快照",
      todayPulse: "今日企业脉搏",
      pendingSignals: "待处理信号",
      recentEvents: "最近组织事件",
      statusOnline: "本地控制台在线",
      policyPending: "2 个策略待发布",
      orgVersion: "Dev Fixture 2026.07.06",
      stats: [
        ["员工", "1,284"],
        ["部门", "86"],
        ["项目组", "42"]
      ],
      pulseStats: [
        ["3", "新入职"],
        ["2", "组织变更"],
        ["1", "项目组新增"],
        ["42/42", "知识空间"]
      ],
      signals: [
        ["external_receipt", "审批回执待返回", "16", "warn"],
        ["connector_attention", "连接器需关注", "2", "warn"],
        ["risk_blocked", "高风险读取已拦截", "4", "ok"],
        ["org_schema_changed", "组织源字段变更", "1", "info"]
      ],
      events: ["示例员工 A 加入研发一部", "MES 项目组新增成员", "财务主管关系已同步", "项目组空间已自动创建"]
    },
    metrics: [
      ["已同步员工", "1,284", "示例组织源 98.4% 匹配", "good"],
      ["已连接系统", "27", "9 个目标实例", "neutral"],
      ["待审批请求", "16", "4 个高风险读取", "warn"],
      ["今日 Agent 访问", "3,642", "拒绝 73 次越权", "good"]
    ],
    resourceMap: {
      title: "企业资源地图",
      desc: "组织、知识库与业务系统的实时连接关系",
      tabs: ["组织", "系统", "风险"],
      aria: "企业资源地图",
      nodes: {
        core: ["Enterprise IAM", "组织图 · 员工 · 项目组"],
        source: ["示例组织源", "1,284 员工"],
        knowledge: ["知识库 AgentRag", "42 组织空间"],
        finance: ["金融财务", "高风险 · 需审批"],
        mes: ["MES 生产", "只读视图"],
        file: ["文件系统", "证据原文"],
        receipt: ["回执通道", "16 待回执"]
      }
    },
    tickets: {
      title: "最近 Access Tickets",
      desc: "任务级授权、审批与数据源访问轨迹",
      filter: "过滤",
      columns: ["Ticket", "员工", "意图", "资源", "决策"],
      rows: [
        ["CT-DEV-0918", "示例员工 A", "我的工作内容是什么", "知识库 + OA", "已授权", "allow"],
        ["CT-DEV-0886", "示例员工 B", "读取财务本月费用", "金融财务", "待回执", "review"],
        ["CT-DEV-0832", "示例员工 C", "查看 MES 异常工单", "MES 生产", "已授权", "allow"],
        ["CT-DEV-0799", "示例员工 D", "导出供应商税号", "金融财务", "已拒绝", "deny"],
        ["CT-DEV-0741", "示例员工 E", "汇总项目组周报", "文件系统", "已授权", "allow"]
      ]
    },
    connectors: {
      title: "连接器健康",
      desc: "目标实例、凭证、同步和测试状态",
      smoke: "Smoke",
      rows: [
        ["示例组织源", "通讯录 1,284 人 · 部门 86 个", "正常", "ok"],
        ["文件系统", "简报原文与证据 · 12.4TB", "正常", "ok"],
        ["金融 K3Cloud", "凭证读取需审批 · 2 个字段脱敏", "需关注", "warn"],
        ["MES 工单只读", "数据库视图 · smoke 通过", "正常", "ok"],
        ["审批回执通道", "待回执 16 · IM 同步开启", "需关注", "warn"]
      ]
    },
    agent: {
      open: "打开 Agent 对话",
      title: "网关 Agent",
      desc: "描述你想接入、调整或排查的事情",
      close: "关闭",
      intro: "我可以帮你创建系统插件、根据接口资料生成配置草稿、排查同步失败，或解释某个 Access Ticket 的链路。",
      prompts: ["生成 MES 插件", "评估字段变更", "解释 Ticket"],
      input: "输入需求，例如：帮我接入新的 OA 回执接口",
      send: "发送",
      sentPrefix: "已记录需求"
    }
  },
  en: {
    source: {
      kind: "development_fixture",
      label: "Development fixture",
      detail: "Gateway API is not connected; this view uses local development fixture data only.",
      updatedAt: "2026-07-06T00:00:00+08:00"
    },
    title: "Enterprise Agent Command Center",
    subtitle: "Knows orgs, systems, permissions, and approvals so every Agent can work safely inside the enterprise.",
    enterprise: "Example Enterprise (local dev)",
    enterpriseAlt: "Example R&D Center",
    privateEnv: "Local development view · Gateway API not connected",
    topbar: {
      enterpriseLabel: "Enterprise",
      search: "Search employees, systems, policies, audit IDs",
      sync: "Sync org",
      notifications: "Notifications",
      avatar: "QA",
      exportAudit: "Export audit"
    },
    pulse: {
      brandName: "Enterprise Gateway",
      brandSub: "Agent Admin",
      currentEnterprise: "Current enterprise",
      orgSnapshot: "Org snapshot",
      todayPulse: "Enterprise pulse",
      pendingSignals: "Pending signals",
      recentEvents: "Recent org events",
      statusOnline: "Local console online",
      policyPending: "2 policies pending release",
      orgVersion: "Dev Fixture 2026.07.06",
      stats: [
        ["Employees", "1,284"],
        ["Departments", "86"],
        ["Project teams", "42"]
      ],
      pulseStats: [
        ["3", "New hires"],
        ["2", "Org changes"],
        ["1", "New team"],
        ["42/42", "Knowledge spaces"]
      ],
      signals: [
        ["external_receipt", "Approval receipts pending", "16", "warn"],
        ["connector_attention", "Connectors need attention", "2", "warn"],
        ["risk_blocked", "High-risk reads blocked", "4", "ok"],
        ["org_schema_changed", "Org source field changed", "1", "info"]
      ],
      events: ["Example employee A joined R&D I", "MES team added a member", "Finance manager line synced", "Project space auto-created"]
    },
    metrics: [
      ["Synced employees", "1,284", "Example org source 98.4% matched", "good"],
      ["Connected systems", "27", "9 target instances", "neutral"],
      ["Pending approvals", "16", "4 high-risk reads", "warn"],
      ["Agent visits today", "3,642", "73 overreach attempts denied", "good"]
    ],
    resourceMap: {
      title: "Enterprise Resource Map",
      desc: "Live relationships between orgs, knowledge spaces, and business systems",
      tabs: ["Org", "Systems", "Risk"],
      aria: "Enterprise resource map",
      nodes: {
        core: ["Enterprise IAM", "Org graph · employees · teams"],
        source: ["Example org source", "1,284 employees"],
        knowledge: ["Knowledge AgentRag", "42 org spaces"],
        finance: ["Kingdee finance", "High risk · approval"],
        mes: ["MES system", "Read-only view"],
        file: ["File system", "Original evidence"],
        receipt: ["Receipt relay", "16 pending"]
      }
    },
    tickets: {
      title: "Recent Access Tickets",
      desc: "Task grants, approvals, and data-source access trails",
      filter: "Filter",
      columns: ["Ticket", "Employee", "Intent", "Resource", "Decision"],
      rows: [
        ["CT-DEV-0918", "Example employee A", "What should I work on?", "Knowledge + OA", "Granted", "allow"],
        ["CT-DEV-0886", "Example employee B", "Read finance expenses", "Kingdee", "Waiting", "review"],
        ["CT-DEV-0832", "Example employee C", "View MES exceptions", "MES", "Granted", "allow"],
        ["CT-DEV-0799", "Example employee D", "Export supplier tax IDs", "Kingdee", "Denied", "deny"],
        ["CT-DEV-0741", "Example employee E", "Summarize team weekly", "File system", "Granted", "allow"]
      ]
    },
    connectors: {
      title: "Connector Health",
      desc: "Target instances, credentials, sync, and smoke status",
      smoke: "Smoke",
      rows: [
        ["Example org source", "Contacts 1,284 · departments 86", "Normal", "ok"],
        ["File system", "Brief originals and evidence · 12.4TB", "Normal", "ok"],
        ["Kingdee K3Cloud", "Voucher reads need approval · 2 masked fields", "Attention", "warn"],
        ["MES read-only orders", "Database view · smoke passed", "Normal", "ok"],
        ["Approval receipt relay", "16 pending · IM sync enabled", "Attention", "warn"]
      ]
    },
    agent: {
      open: "Open Agent chat",
      title: "Gateway Agent",
      desc: "Describe the integration, change, or issue you want to handle",
      close: "Close",
      intro: "I can create connector drafts, generate instance configs from interface docs, diagnose sync failures, or explain an Access Ticket chain.",
      prompts: ["Generate MES connector", "Assess field change", "Explain Ticket"],
      input: "Type a request, for example: connect a new OA receipt API",
      send: "Send",
      sentPrefix: "Request captured"
    }
  }
};

type ViteImportMeta = ImportMeta & {
  env?: {
    VITE_AGENTNEXUS_CONSOLE_OVERVIEW_URL?: string;
  };
};

const overviewEndpoint = (import.meta as ViteImportMeta).env?.VITE_AGENTNEXUS_CONSOLE_OVERVIEW_URL ?? "/api/console/overview";

export async function loadConsoleOverview(locale: Locale, endpoint = overviewEndpoint): Promise<ConsoleOverview> {
  if (!endpoint) {
    return developmentFixtures[locale];
  }

  try {
    const url = new URL(endpoint, window.location.origin);
    url.searchParams.set("locale", locale);
    const response = await fetch(url, { headers: { Accept: "application/json" } });

    if (!response.ok) {
      return developmentFixtures[locale];
    }

    const payload = (await response.json()) as ConsoleOverview;
    return {
      ...payload,
      source: {
        ...payload.source,
        kind: "api"
      }
    };
  } catch {
    return developmentFixtures[locale];
  }
}
