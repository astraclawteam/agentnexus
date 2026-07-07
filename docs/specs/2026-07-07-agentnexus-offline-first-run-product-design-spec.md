# AgentNexus Offline-First First-Run Product Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this spec task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Design the offline-deployment-first first-run product experience so a customer administrator can independently initialize AgentNexus, create an enterprise tenant, configure safe secret references, import organization data, validate connectors, start the Gateway Agent, and enter a live console without vendor assistance.

**Architecture:** Treat first-run as a product workflow, not a collection of settings pages. The UI must orchestrate existing and planned backend primitives: setup status, local admin session, enterprise tenant, secret provider, org import preview/confirm, connector smoke, Gateway Agent dry-run, and live console overview. All customer secrets stay outside the frontend and repository; the browser only handles secret references and safe metadata.

**Tech Stack:** React + TypeScript + Vite console, Go `gateway-api`, Go `gateway-agent`, local/offline private-dev profile, Docker Compose/Helm delivery, environment or local encrypted Secret Provider, PostgreSQL/NATS readiness checks, Vitest and browser automation for acceptance.

---

## 1. Product Positioning

AgentNexus must be usable in an offline or private deployment before it is polished as SaaS. In private delivery, the customer often receives an installation package, runs it inside their network, and expects an administrator to finish configuration without direct engineering support.

Therefore first-run must be:

- **Self-explanatory:** every screen says what this step does, why it matters, and what to click.
- **Offline aware:** no assumption that external SaaS endpoints, docs, telemetry, or public internet are reachable.
- **Enterprise-tenant centered:** every setup action belongs to a company-level tenant boundary.
- **Secret safe:** no raw key/token entry into source code or persisted browser state.
- **Recoverable:** failures explain what is wrong and how to fix it locally.
- **Verifiable:** every `configured` state must be backed by an API response, not fixture data.

## 2. Primary Users

### Customer Deployment Admin

Owns local installation, Docker/Helm runtime, first login, environment variables, and secret provider setup.

Needs:

- clear health checks,
- exact missing dependency messages,
- local-only configuration steps,
- no hidden cloud requirements.

### Enterprise System Admin

Owns OA/IM/org source, employee directory, connector credentials, and approval systems.

Needs:

- vendor/source-specific setup guidance,
- preview before import,
- safe confirmation,
- ability to retry after fixing credentials.

### Internal Implementation / Support Engineer

Uses the same UI during private delivery support or customer onboarding.

Needs:

- visible state,
- reproducible diagnostics,
- downloadable/local support bundle without secrets.

## 3. Non-Goals

- Do not build a marketing landing page.
- Do not require internet access to complete setup.
- Do not paste real tokens, API keys, or customer secrets into the repository.
- Do not hide incomplete backend capabilities behind fake success states.
- Do not mark the system production-ready after only organization import.
- Do not implement vendor OAuth, commercial connectors, or production deployment automation in this spec unless the UI labels the unavailable capability explicitly and honestly.

## 4. First-Run Information Architecture

The application must have two high-level modes:

| Mode | Entry Condition | Primary Screen |
| --- | --- | --- |
| `setup_required` | no valid local admin or enterprise tenant | First-run shell |
| `configured` | admin session + enterprise tenant + confirmed org import | Enterprise console |

First-run shell contains:

1. **Local Admin Access**
2. **Enterprise Tenant**
3. **Environment Check**
4. **Secret Provider**
5. **Organization Import**
6. **Connector Verification**
7. **Gateway Agent Dry Run**
8. **Enter Console**

The console contains:

1. **Setup Completion Checklist**
2. **Enterprise Resource Map**
3. **Access Tickets**
4. **Connector Health**
5. **Gateway Agent**
6. **Audit / Support Diagnostics**

## 5. Complete User Journey

### Step 0: Open Local URL

User opens:

```text
http://127.0.0.1:5173/
```

Expected first impression:

- Product name: `AgentNexus 企业网关`
- Deployment mode badge: `离线部署 / 本地私有环境`
- Current backend status: `gateway-api reachable` or `需要启动 gateway-api`
- One primary action: `开始首次配置`

The page must not show dashboard metrics, demo employees, fake tickets, or connector health before setup.

### Step 1: Local Admin Initialization / Login

Purpose:

Create or authenticate the local administrator who can configure the offline installation.

Screen behavior:

- If no admin exists:
  - title: `创建本地管理员`
  - fields:
    - admin name
    - admin user id
    - password or setup code, depending on deployment profile
  - primary action: `创建管理员并继续`
- If admin exists:
  - title: `管理员登录`
  - fields:
    - user id
    - password / one-time setup code
  - primary action: `登录并继续`

Design rule:

- Explain that this account is local to the private deployment.
- Do not require cloud account login.
- If auth is not implemented yet, show an honest `开发模式管理员会话` state rather than pretending login exists.

### Step 2: Enterprise Tenant Creation

Purpose:

Create the company-level tenant boundary. All users, departments, connectors, policies, tickets, agent runs, and audit events belong to this tenant.

Screen copy:

```text
初始化企业租户
为一个企业创建独立租户空间。后续组织、连接器、策略和 Agent 运行都会归属到这个企业。
```

Fields:

- enterprise tenant id
- enterprise tenant name
- environment label
- tenant admin user id

Primary action:

```text
保存租户并继续
```

Success state:

```text
企业租户已创建。接下来校验密钥引用。
```

Acceptance:

- User understands this is SaaS/private multi-enterprise semantics, not a generic settings object.
- `enterprise_id` is visible throughout setup and console.

### Step 3: Environment Check

Purpose:

Tell the customer whether the offline runtime is healthy enough to continue.

Checks:

- gateway-api reachable
- gateway-agent reachable
- PostgreSQL configured / reachable
- NATS configured / reachable
- object storage configured / reachable
- Docker Compose or Helm profile rendered
- system clock and local hostname readable
- configured secret provider mode

Status levels:

| Status | Meaning | UI |
| --- | --- | --- |
| `ready` | can continue | green check |
| `warning` | can continue with limitation | yellow warning |
| `blocked` | cannot continue | red block + exact fix |

Example blocked message:

```text
gateway-api 未连接。请在服务器上启动 gateway-api，或检查 8080 端口是否可访问。
```

Primary action:

```text
重新检查环境
```

Navigation rule:

- Block organization import if `gateway-api` is unreachable.
- Allow UI preview only in explicit `Demo fixture` mode, visually separated.

### Step 4: Secret Provider / API Key Configuration

Purpose:

Teach the user where API keys are configured without asking them to paste raw secrets into the browser.

Screen copy:

```text
配置密钥引用
AgentNexus 不在前端保存真实密钥。请在部署环境或密钥管理器中配置真实值，这里只填写引用。
```

Supported secret refs:

```text
secret://env/LLMROUTER_API_KEY
secret://env/AGENTNEXUS_OA_TOKEN
secret://env/AGENTNEXUS_FILE_STORAGE_TOKEN
```

Fields:

- model provider / llmrouter key ref
- OA/org source credential ref
- connector credential ref
- optional secret provider mode selector:
  - env
  - local encrypted
  - Kubernetes Secret
  - Vault-compatible, future

Primary action:

```text
校验密钥引用并继续
```

Validation result:

- `已解析`: ref exists and can be resolved
- `缺失`: env/secret name not found
- `格式错误`: does not start with accepted prefix
- `不支持`: provider mode does not support this ref

Hard rules:

- Raw token-like values must be rejected or warned before submit.
- Responses must never include resolved secret values.
- UI must never log resolved secret values.

### Step 5: Organization Source Import

Purpose:

Import company employees, departments, memberships, and external identities into the enterprise tenant.

Screen structure:

1. Select source:
   - OA HTTP
   - 企业微信
   - 钉钉
   - 飞书
2. Show source-specific guidance.
3. Configure safe refs/endpoints.
4. Preview import.
5. Confirm import.

For open-core current implementation:

- `OA HTTP` is fully usable with normalized endpoints.
- WeCom/DingTalk/Feishu may be shown as selectable only if backend supports the configured mode.
- If official adapter is not implemented, UI must say:

```text
当前版本通过通用 OA HTTP 桥接接入。正式企业微信/钉钉/飞书适配器尚未启用。
```

Preview result:

```text
将导入 1284 名员工、86 个部门、42 条成员关系。
```

Conflict result:

```text
发现 3 个冲突，需要处理后才能确认导入。
```

Primary actions:

- `预览组织数据`
- `确认导入并继续`
- `返回修改来源`

Acceptance:

- Preview is non-persistent.
- Confirm writes org graph to the selected enterprise tenant.
- Console counts after confirm come from live API, not fixture data.

### Step 6: Connector Verification

Purpose:

Prove that at least one connector/plugin can be validated and smoke-tested in the offline deployment.

Screen behavior:

- Empty state:

```text
还没有连接器实例。添加第一个连接器来验证插件系统是否可用。
```

- Manifest validation:
  - upload/paste manifest
  - show resource names
  - show scopes/operations
  - show validation errors

- Instance smoke:
  - choose manifest
  - choose resource
  - choose operation
  - choose credential ref
  - run smoke

Primary actions:

- `校验连接器 Manifest`
- `运行 Smoke 测试`
- `保存连接器实例`

Acceptance:

- UI says whether this is a dev smoke, not production certification.
- Secret value is never shown.
- Failed smoke explains exact next fix.

### Step 7: Gateway Agent First Deployment Dry Run

Purpose:

Validate that the Gateway Agent can plan an initial deployment or configuration run without executing unsafe production actions.

Screen copy:

```text
运行 Agent 首次部署计划
Agent 会生成 dry-run 计划，不会自动执行 Docker、Helm 或生产变更。
```

Primary action:

```text
生成部署 Dry Run 计划
```

Expected plan steps:

- validate compose config
- start gateway-api
- start gateway-agent
- start connector-worker
- verify console overview API
- require human confirmation before apply

Acceptance:

- UI displays plan steps.
- Plan mode is clearly labeled `dry_run`.
- Any future apply action requires explicit human confirmation.

### Step 8: Enter Live Console

Purpose:

End setup only when the system has enough real state to be useful.

Entry conditions:

- local admin session exists or dev admin mode explicitly enabled
- enterprise tenant exists
- environment critical checks pass
- secret refs validated or intentionally skipped with warning
- org import confirmed

Console must show:

- enterprise name
- source badge: `Gateway API 实时数据`
- setup completion checklist
- org counts from live graph
- no demo metrics unless `demo=true`

If setup is incomplete, console must show a persistent checklist:

```text
下一步：校验连接器
原因：没有连接器实例，Agent 暂时无法读取企业系统数据。
```

## 6. Login And Session Product Contract

### Local Admin Modes

| Mode | Intended Use | UX |
| --- | --- | --- |
| `dev_admin` | local development | badge: `开发管理员会话` |
| `local_admin` | private deployment | login screen |
| `sso_admin` | future enterprise SSO | disabled or hidden until implemented |

### Session Rules

- User must know who they are acting as.
- Header must show admin identity after login.
- Agent run requests must include `actor_user_id`.
- Audit events must include admin/session identity.
- If real auth is not implemented, product must not pretend it is secure.

## 7. Empty State Design

Every empty panel must answer:

1. What is missing?
2. Why does it matter?
3. What should I click next?

Examples:

### Access Tickets Empty

```text
暂无授权工单
当 Agent 或用户请求访问企业系统时，这里会显示审批、授权和拒绝记录。
下一步：配置策略与连接器。
```

Action:

```text
配置策略
```

### Connector Health Empty

```text
还没有连接器
连接器让 Agent 安全访问文件、数据库、OA 和业务系统。
下一步：添加第一个连接器。
```

Action:

```text
添加连接器
```

### Audit Empty

```text
暂无审计事件
完成组织导入、连接器 smoke 或 Agent run 后会产生审计记录。
```

Action:

```text
运行一次 Agent dry-run
```

## 8. Navigation Model

Top-level navigation after login:

- `首次配置` if setup incomplete
- `控制台`
- `组织`
- `连接器`
- `策略`
- `Agent`
- `审计`
- `系统设置`

During first-run:

- Do not expose every nav item as active workspace.
- Show setup steps as primary navigation.
- Allow exit to console only if setup can safely show partial state.

## 9. Error And Recovery Design

### Error Message Pattern

Every error must include:

```text
发生了什么
为什么会阻塞
怎么修复
重新检查按钮
```

### Examples

Missing env secret:

```text
没有找到 AGENTNEXUS_OA_TOKEN
组织导入需要这个密钥引用。
请在部署环境中设置 AGENTNEXUS_OA_TOKEN，然后点击重新校验。
```

OA endpoint unreachable:

```text
无法连接组织来源
gateway-api 可以运行，但 OA HTTP 地址不可访问。
请确认 Base URL、网络、防火墙和 token 后重试。
```

Docker unavailable:

```text
未检测到 Docker
首次部署 dry-run 需要验证 compose 配置。
请安装或启动 Docker Desktop，或切换到 Helm 验证模式。
```

## 10. Offline Deployment Requirements

The first-run UI must not depend on:

- public CDN,
- public documentation URLs,
- cloud telemetry,
- external auth provider,
- external image assets,
- hosted feature flags.

All required copy, icons, styles, and help content must be bundled.

The application may link to local docs:

```text
/docs/first-run-configuration
/docs/private-dev-deployment
/docs/support-bundle
```

## 11. Support Bundle

First-run should eventually provide a support bundle action:

```text
导出诊断包
```

Bundle may include:

- service health snapshot,
- setup state,
- dependency versions,
- compose/helm profile summary,
- recent audit event ids,
- redacted error logs.

Bundle must not include:

- raw secrets,
- raw tokens,
- customer employee PII unless explicitly selected,
- private endpoints unless redacted or confirmed.

## 12. State Machine

```text
boot
  -> api_unavailable
  -> admin_required
  -> tenant_required
  -> environment_check
  -> secrets_required
  -> org_import_required
  -> connector_verification_optional
  -> agent_dry_run_optional
  -> configured
```

### Required States

| State | User Sees | Required Action |
| --- | --- | --- |
| `api_unavailable` | backend not reachable | start/check gateway-api |
| `admin_required` | create/login local admin | authenticate |
| `tenant_required` | create enterprise tenant | save tenant |
| `environment_check` | local service status | fix blocked checks |
| `secrets_required` | secret ref form | validate refs |
| `org_import_required` | source selector + preview | confirm import |
| `configured` | live console | operate system |

Optional but visible:

- connector verification
- gateway-agent dry run
- audit export

## 13. API Product Requirements

The product design expects these API surfaces.

### Setup

- `GET /api/setup/status`
- `POST /api/setup/admin/init`
- `POST /api/setup/login`
- `POST /api/setup/enterprise`
- `POST /api/setup/secrets/validate`
- `GET /api/setup/environment`

### Organization

- `POST /api/org/import/preview`
- `POST /api/org/import/confirm`
- `GET /api/org/graph`

### Connectors

- `POST /api/connectors/packages/validate`
- `POST /api/connectors/instances/draft`
- `POST /api/connectors/instances/{id}:smoke`
- `POST /api/connectors/instances/{id}:confirm`

### Agent

- `POST /v1/agent/runs`
- `POST /v1/agent/runs/{id}/messages`
- `POST /v1/agent/deployments/first-run:plan`

### Console

- `GET /api/console/overview?enterprise_id=...`
- `GET /api/console/setup-checklist?enterprise_id=...`

## 14. UX Acceptance Criteria

The first-run experience is acceptable only if a new customer admin can answer these from the UI:

- What is AgentNexus asking me to configure first?
- Is this a local/offline deployment or cloud login?
- Which enterprise tenant am I configuring?
- Where do API keys go?
- Why am I not pasting secrets into this page?
- Which organization source should I choose?
- What will be imported before I confirm?
- What is safe to skip?
- What is blocked and how do I fix it?
- When am I allowed to enter the console?

## 15. Visual Design Requirements

- No landing page or marketing hero.
- First screen must be the actual setup workspace.
- Use task-oriented panels, not decorative cards.
- Primary action must be visually obvious and unique per step.
- Secondary actions must not compete with the primary action.
- Avoid icon-only actions for first-run.
- Keep dense enterprise-console style, but with enough explanation for a first-time admin.
- Chinese and English copy must both be complete.
- No visible mojibake or mixed Chinese/English except technical identifiers like `secret://env`.

## 16. Browser Automation Acceptance Path

An automated browser test must verify:

1. Open `http://127.0.0.1:5173/`.
2. If API is unavailable, see a blocked environment screen.
3. If API is available but unconfigured, see `初始化企业租户`.
4. Create or log in local admin.
5. Create enterprise tenant.
6. Validate secret refs.
7. Preview OA HTTP organization import.
8. Confirm import.
9. Enter console.
10. Assert console source is `Gateway API 实时数据`.
11. Assert employee/department counts come from live API.
12. Assert no demo numbers like `1,284` or `3,642` appear unless demo mode is explicitly enabled.
13. Open Gateway Agent.
14. Generate first-deployment dry-run plan.
15. Verify plan is `dry_run` and asks for human confirmation before apply.

## 17. Implementation Milestones

### P0: Product-Correct First-Run Shell

- Replace flat first-run forms with guided tenant onboarding.
- Add clear local/offline mode.
- Add one visible primary action per step.
- Add complete Chinese/English copy.
- Add browser verification for setup path.

### P0: Local Admin And Session Honesty

- Implement or honestly label dev admin mode.
- Do not imply production auth if unavailable.
- Carry `actor_user_id` into setup, org import, connector, and agent actions.

### P0: Environment And Secret Diagnostics

- Add environment check endpoint and UI.
- Expand secret ref validation with actionable errors.
- Block raw secret submission.

### P0: Live Console With Checklist

- Add setup checklist API or derive checklist from setup status.
- Show empty states with next actions.
- Hide/disable incomplete actions with honest labels.

### P1: Connector And Agent Guided Setup

- Add connector verification wizard.
- Add Gateway Agent dry-run panel.
- Show tool catalog and dry-run plan.

### P1: Support Bundle

- Add redacted diagnostics export.
- Include local health and setup state.

## 18. Definition Of Done

- `npm test --workspace packages/enterprise-gateway-console` passes.
- `npm run build --workspace packages/enterprise-gateway-console` passes.
- `go test ./...` passes for affected backend changes.
- Browser automation proves the first-run path.
- First-run screens contain no mock metrics as live data.
- Chinese and English first-run copy are complete.
- A reviewer can configure the local system using UI prompts without reading source code.
- Documentation and UI agree on where API keys and OA credentials are configured.

## 19. Open Decisions

These must be decided before full implementation:

1. Local admin credential mechanism for private deployment:
   - setup code,
   - local password,
   - external enterprise SSO later.
2. Secret provider priority:
   - env first,
   - local encrypted first,
   - Kubernetes Secret first.
3. Whether connector verification is mandatory before entering console or marked as recommended.
4. Whether Gateway Agent dry-run is mandatory before entering console or shown as next recommended action.
5. How support bundle redaction rules are configured by customer admins.

## 20. Recommended Next Spec

After this product spec is approved, create an implementation spec:

```text
2026-07-07-agentnexus-offline-first-run-implementation-spec.md
```

It should split work into:

1. frontend IA and copy,
2. local admin/session API,
3. environment diagnostics API,
4. setup checklist API,
5. connector/agent guided setup panels,
6. browser automation.
