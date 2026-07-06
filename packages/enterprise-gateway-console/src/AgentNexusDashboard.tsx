import { useMemo, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";
import { AccessTicketsTable } from "./AccessTicketsTable";
import { ConnectorHealth } from "./ConnectorHealth";
import { EnterprisePulse } from "./EnterprisePulse";
import { GatewayAgentLauncher } from "./GatewayAgentLauncher";
import { ResourceMap } from "./ResourceMap";

type Locale = "zh" | "en";

const localeNames: Record<Locale, string> = {
  zh: "中文",
  en: "EN"
};

const copy = {
  zh: {
    title: "企业智能行政中枢",
    subtitle: "懂组织、懂系统、懂权限、懂审批，负责让所有 Agent 安全地在企业里办事。",
    enterprise: "顺视智能制造集团",
    enterpriseAlt: "华东研发中心",
    privateEnv: "私有化网关 · 生产环境",
    topbar: {
      enterpriseLabel: "企业",
      search: "搜索员工、系统、策略、审计号",
      sync: "同步组织",
      notifications: "通知",
      avatar: "林",
      exportAudit: "导出审计"
    },
    pulse: {
      brandSub: "Agent Admin",
      currentEnterprise: "当前企业",
      orgSnapshot: "组织快照",
      todayPulse: "今日企业脉搏",
      pendingSignals: "待处理信号",
      recentEvents: "最近组织事件",
      statusOnline: "私有化网关在线",
      policyPending: "2 个策略待发布",
      orgVersion: "Org Graph 2026.07.04-18",
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
      events: ["张予安加入研发一部", "MES 项目组新增成员", "财务部主管关系已同步", "项目组空间已自动创建"]
    },
    metrics: [
      ["已同步员工", "1,284", "飞书 98.4% 匹配", "good"],
      ["已连接系统", "27", "9 个生产实例", "neutral"],
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
        source: ["飞书组织源", "1,284 员工"],
        knowledge: ["知识库 AgentRag", "42 组织空间"],
        finance: ["金蝶财务", "高风险 · 需审批"],
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
        ["CT-240704-0918", "张予安", "我的工作内容是什么", "知识库 + OA", "已授权", "allow"],
        ["CT-240704-0886", "陈可", "读取财务本月费用", "金蝶财务", "待回执", "review"],
        ["CT-240704-0832", "林舟", "查看 MES 异常工单", "MES 生产", "已授权", "allow"],
        ["CT-240704-0799", "周宁", "导出供应商税号", "金蝶财务", "已拒绝", "deny"],
        ["CT-240704-0741", "韩越", "汇总项目组周报", "文件系统", "已授权", "allow"]
      ]
    },
    connectors: {
      title: "连接器健康",
      desc: "生产实例、凭证、同步和测试状态",
      smoke: "Smoke",
      rows: [
        ["飞书组织源", "通讯录 1,284 人 · 部门 86 个", "正常", "ok"],
        ["文件系统", "简报原文与证据 · 12.4TB", "正常", "ok"],
        ["金蝶 K3Cloud", "凭证读取需审批 · 2 个字段脱敏", "需关注", "warn"],
        ["MES 工单只读", "数据库视图 · smoke 通过", "正常", "ok"],
        ["审批回执通道", "待回执 16 · IM 同步开启", "需关注", "warn"]
      ]
    },
    agent: {
      open: "打开 Agent 对话",
      title: "网关 Agent",
      desc: "描述你想接入、调整或排查的事情",
      close: "关闭",
      intro:
        "我可以帮你创建系统插件、根据接口资料生成配置草稿、排查同步失败，或解释某个 Access Ticket 的链路。",
      prompts: ["生成 MES 插件", "评估字段变更", "解释 Ticket"],
      input: "输入需求，例如：帮我接入新的 OA 回执接口",
      send: "发送",
      sentPrefix: "已记录需求"
    }
  },
  en: {
    title: "Enterprise Agent Command Center",
    subtitle: "Knows orgs, systems, permissions, and approvals so every Agent can work safely inside the enterprise.",
    enterprise: "Sunvision Intelligent Manufacturing Group",
    enterpriseAlt: "East China R&D Center",
    privateEnv: "Private gateway · production",
    topbar: {
      enterpriseLabel: "Enterprise",
      search: "Search employees, systems, policies, audit IDs",
      sync: "Sync org",
      notifications: "Notifications",
      avatar: "Lin",
      exportAudit: "Export audit"
    },
    pulse: {
      brandSub: "Agent Admin",
      currentEnterprise: "Current enterprise",
      orgSnapshot: "Org snapshot",
      todayPulse: "Enterprise pulse",
      pendingSignals: "Pending signals",
      recentEvents: "Recent org events",
      statusOnline: "Private gateway online",
      policyPending: "2 policies pending release",
      orgVersion: "Org Graph 2026.07.04-18",
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
      events: ["Zhang Yuan joined R&D I", "MES team added a member", "Finance manager line synced", "Project space auto-created"]
    },
    metrics: [
      ["Synced employees", "1,284", "Feishu 98.4% matched", "good"],
      ["Connected systems", "27", "9 production instances", "neutral"],
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
        source: ["Feishu org source", "1,284 employees"],
        knowledge: ["Knowledge AgentRag", "42 org spaces"],
        finance: ["Kingdee finance", "High risk · approval"],
        mes: ["MES production", "Read-only view"],
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
        ["CT-240704-0918", "Zhang Yuan", "What should I work on?", "Knowledge + OA", "Granted", "allow"],
        ["CT-240704-0886", "Chen Ke", "Read finance expenses", "Kingdee", "Waiting", "review"],
        ["CT-240704-0832", "Lin Zhou", "View MES exceptions", "MES", "Granted", "allow"],
        ["CT-240704-0799", "Zhou Ning", "Export supplier tax IDs", "Kingdee", "Denied", "deny"],
        ["CT-240704-0741", "Han Yue", "Summarize team weekly", "File system", "Granted", "allow"]
      ]
    },
    connectors: {
      title: "Connector Health",
      desc: "Production instances, credentials, sync, and smoke status",
      smoke: "Smoke",
      rows: [
        ["Feishu org source", "Contacts 1,284 · departments 86", "Normal", "ok"],
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
      intro:
        "I can create connector drafts, generate instance configs from interface docs, diagnose sync failures, or explain an Access Ticket chain.",
      prompts: ["Generate MES connector", "Assess field change", "Explain Ticket"],
      input: "Type a request, for example: connect a new OA receipt API",
      send: "Send",
      sentPrefix: "Request captured"
    }
  }
} satisfies Record<Locale, Record<string, unknown>>;

export function AgentNexusDashboard() {
  const [locale, setLocale] = useState<Locale>("zh");
  const t = useMemo(() => copy[locale], [locale]);

  return (
    <main className="console-shell" lang={locale === "zh" ? "zh-CN" : "en"}>
      <EnterprisePulse copy={t} />
      <section className="workspace">
        <header className="topbar">
          <label className="company-switcher">
            <span className="icon icon-building" aria-hidden="true" />
            <span className="sr-only">{t.topbar.enterpriseLabel}</span>
            <select aria-label={t.topbar.enterpriseLabel}>
              <option>{t.enterprise}</option>
              <option>{t.enterpriseAlt}</option>
            </select>
          </label>
          <label className="topbar-search">
            <span className="icon icon-search" aria-hidden="true" />
            <Input type="search" aria-label={t.topbar.search} placeholder={t.topbar.search} />
          </label>
          <button className="icon-button" title={t.topbar.sync} aria-label={t.topbar.sync}>
            <span className="icon icon-sync" aria-hidden="true" />
          </button>
          <button className="icon-button" title={t.topbar.notifications} aria-label={t.topbar.notifications}>
            <span className="icon icon-bell" aria-hidden="true" />
            <span className="badge-dot" />
          </button>
          <div className="locale-switch" role="group" aria-label="Language">
            {(Object.keys(localeNames) as Locale[]).map((nextLocale) => (
              <button
                className={nextLocale === locale ? "is-selected" : ""}
                key={nextLocale}
                type="button"
                onClick={() => setLocale(nextLocale)}
              >
                {localeNames[nextLocale]}
              </button>
            ))}
          </div>
          <div className="avatar" aria-label={t.topbar.avatar}>
            {t.topbar.avatar}
          </div>
        </header>

        <section className="page-head">
          <div>
            <h1>{t.title}</h1>
            <p>{t.subtitle}</p>
          </div>
          <div className="head-actions">
            <Button className="ghost-button" variant="ghost">
              <span className="icon icon-download" aria-hidden="true" />
              {t.topbar.exportAudit}
            </Button>
          </div>
        </section>

        <section className="metrics" aria-label="Gateway metrics">
          {t.metrics.map(([label, value, note, tone]) => (
            <article className="metric-card" key={label}>
              <div className="metric-label">{label}</div>
              <div className="metric-value">{value}</div>
              <div className={`metric-foot ${tone}`}>{note}</div>
            </article>
          ))}
        </section>

        <section className="main-grid single">
          <ResourceMap copy={t.resourceMap} />
        </section>

        <section className="lower-grid">
          <AccessTicketsTable copy={t.tickets} />
          <ConnectorHealth copy={t.connectors} />
        </section>
      </section>

      <GatewayAgentLauncher copy={t.agent} />
    </main>
  );
}
