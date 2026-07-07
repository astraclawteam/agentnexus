import { useMemo, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";
import type {
  EnterpriseSetupRequest,
  OrgImportConfirmRequest,
  OrgImportPreviewRequest,
  OrgImportPreviewResponse,
  SecretRefsValidateResponse
} from "./setup-api";
import { defaultSetupAPI } from "./setup-api";
import type { Locale } from "./console-data";

type FirstRunSetupAPI = {
  saveEnterpriseSetup(input: EnterpriseSetupRequest): Promise<unknown>;
  loadSetupEnvironment(): Promise<unknown>;
  validateSecretRefs(input: { refs: Record<string, string> }): Promise<SecretRefsValidateResponse>;
  previewOrgImport(input: OrgImportPreviewRequest): Promise<OrgImportPreviewResponse>;
  confirmOrgImport(input: OrgImportConfirmRequest): Promise<unknown>;
};

type FirstRunSetupProps = {
  locale: Locale;
  api?: FirstRunSetupAPI;
  onComplete: () => void | Promise<void>;
  onOpenDemo?: () => void;
  onExitSetup?: () => void;
};

type StepKey = "tenant" | "environment" | "secrets" | "org" | "console";

const stepOrder: StepKey[] = ["tenant", "environment", "secrets", "org", "console"];

const copy = {
  zh: {
    title: "初始化企业租户",
    subtitle: "为一个企业创建独立租户空间，再导入组织、校验密钥并进入实时控制台。",
    demoDashboard: "查看演示仪表盘（开发模式）",
    steps: {
      tenant: "企业租户",
      environment: "环境检查",
      secrets: "密钥引用",
      org: "组织导入",
      console: "进入控制台"
    },
    tenantTitle: "先创建企业租户",
    tenantBody: "这里创建的是 SaaS 形态下的企业工作区。后续组织、连接器、策略和 Agent 运行都会归属到这个企业。",
    tenantID: "企业租户 ID",
    tenantName: "企业租户名称",
    adminUserID: "租户管理员用户 ID",
    environmentLabel: "环境标识",
    editableHint: "保存前可编辑",
    saveTenant: "保存租户并继续",
    environmentTitle: "检查本地离线运行环境",
    environmentBody: "先确认 gateway-api、gateway-agent、数据库、消息队列和密钥提供方处于可继续配置的状态。",
    recheckEnvironment: "重新检查环境并继续",
    secretsTitle: "校验密钥引用",
    secretsBody: "页面只校验 secret 引用，不保存真实密钥。真实值来自部署环境或密钥管理器。",
    llmrouterRef: "llmrouter API key 密钥引用",
    oaRef: "OA token 密钥引用",
    connectorRef: "连接器凭证密钥引用",
    validateSecrets: "校验密钥并继续",
    orgTitle: "预览组织导入",
    orgBody: "选择企业的组织来源，先预览员工、部门和成员关系。预览不会写入组织图。",
    provider: "组织来源",
    baseURL: "Base URL",
    departmentsPath: "部门路径",
    employeesPath: "员工路径",
    previewImport: "预览组织数据",
    consoleTitle: "确认导入并进入控制台",
    consoleBody: "确认后，这批组织数据会写入当前企业租户，并成为控制台的实时组织图。",
    confirmImport: "确认导入并进入控制台",
    guidanceTitle: "当前步骤",
    tenantGuidance: "确认企业名称和管理员。企业租户是所有后续配置的边界。",
    environmentGuidance: "这里检查的是本地私有化部署运行环境。阻塞项需要先修复，警告项可以在 private-dev 下继续。",
    secretsGuidance: "只填写 secret://env/... 这样的引用。不要在页面里输入真实 API key 或 token。",
    orgGuidance: "当前 open-core 版本使用通用 OA HTTP 结构。企微、钉钉、飞书专用适配后续可替换。",
    consoleGuidance: "检查预览数量，确认无误后进入控制台继续配置连接器和策略。",
    saved: "企业租户已保存",
    environmentReady: "环境检查完成",
    validated: "密钥引用已校验",
    unresolved: "有密钥引用未解析，请检查环境变量",
    ready: (employees: number, departments: number, memberships: number) =>
      `将向当前租户导入 ${employees} 名员工、${departments} 个部门、${memberships} 条成员关系。`
  },
  en: {
    title: "Set up an enterprise tenant",
    subtitle: "Create one company-scoped tenant workspace, then import organization data and enter the live console.",
    demoDashboard: "View demo dashboard (dev mode)",
    steps: {
      tenant: "Enterprise tenant",
      environment: "Environment check",
      secrets: "Secret refs",
      org: "Organization import",
      console: "Live console"
    },
    tenantTitle: "Create the enterprise tenant first",
    tenantBody: "This creates one tenant workspace for a company. Organization data, connectors, policy, and Agent runs will be scoped to this enterprise.",
    tenantID: "Enterprise tenant ID",
    tenantName: "Enterprise tenant name",
    adminUserID: "Tenant admin user ID",
    environmentLabel: "Environment label",
    editableHint: "Editable before saving",
    saveTenant: "Save tenant and continue",
    environmentTitle: "Check the local offline runtime",
    environmentBody: "Confirm the local offline runtime is healthy enough before configuring credentials and organization data.",
    recheckEnvironment: "Recheck environment and continue",
    secretsTitle: "Validate secret references",
    secretsBody: "Secret values stay outside the browser and repository. This page only validates references such as secret://env/LLMROUTER_API_KEY.",
    llmrouterRef: "llmrouter API key secret ref",
    oaRef: "OA token secret ref",
    connectorRef: "Connector credential secret ref",
    validateSecrets: "Validate refs and continue",
    orgTitle: "Preview organization import",
    orgBody: "Choose the company's organization source and preview employees, departments, and memberships before writing anything.",
    provider: "Organization source",
    baseURL: "Base URL",
    departmentsPath: "Departments path",
    employeesPath: "Employees path",
    previewImport: "Preview organization data",
    consoleTitle: "Confirm import and enter the console",
    consoleBody: "After confirmation, this organization snapshot becomes the live org graph for the current enterprise tenant.",
    confirmImport: "Confirm import and enter console",
    guidanceTitle: "Current step",
    tenantGuidance: "Confirm the company name and tenant admin. This tenant boundary owns all later configuration.",
    environmentGuidance: "This checks the private deployment runtime. Blocked checks must be fixed first; warnings can continue in private-dev.",
    secretsGuidance: "Use secret://env/... references only. Do not paste real API keys or tokens into the browser.",
    orgGuidance: "The open-core build uses a generic OA HTTP shape now. Dedicated WeCom, DingTalk, and Feishu adapters can replace it later.",
    consoleGuidance: "Review the preview counts, then enter the live console to continue connector and policy setup.",
    saved: "Enterprise tenant saved",
    environmentReady: "Environment check completed",
    validated: "Secret refs validated",
    unresolved: "Some secret refs are unresolved",
    ready: (employees: number, departments: number, memberships: number) =>
      `Ready to import ${employees} employee, ${departments} department, and ${memberships} membership into this tenant.`
  }
};

export function FirstRunSetup({ locale, api = defaultSetupAPI, onComplete, onOpenDemo, onExitSetup }: FirstRunSetupProps) {
  const t = copy[locale];
  const returnConsoleLabel = locale === "zh" ? "返回实时控制台" : "Return to live console";
  const [step, setStep] = useState<StepKey>("tenant");
  const [enterpriseID, setEnterpriseID] = useState("ent_dev");
  const [enterpriseName, setEnterpriseName] = useState(locale === "zh" ? "顺视智能制造集团" : "Local Development Enterprise");
  const [adminUserID, setAdminUserID] = useState("admin_dev");
  const [environmentLabel, setEnvironmentLabel] = useState(locale === "zh" ? "私有化环境" : "private-dev");
  const [llmrouterRef, setLLMRouterRef] = useState("secret://env/LLMROUTER_API_KEY");
  const [oaRef, setOARef] = useState("secret://env/AGENTNEXUS_OA_TOKEN");
  const [connectorRef, setConnectorRef] = useState("secret://env/AGENTNEXUS_FILE_STORAGE_TOKEN");
  const [provider, setProvider] = useState("oa_http");
  const [baseURL, setBaseURL] = useState("http://127.0.0.1:18080");
  const [departmentsPath, setDepartmentsPath] = useState("/departments");
  const [employeesPath, setEmployeesPath] = useState("/employees");
  const [status, setStatus] = useState("");
  const [preview, setPreview] = useState<OrgImportPreviewResponse | null>(null);

  const activeIndex = stepOrder.indexOf(step);
  const guidance = useMemo(() => {
    if (step === "tenant") return t.tenantGuidance;
    if (step === "environment") return t.environmentGuidance;
    if (step === "secrets") return t.secretsGuidance;
    if (step === "org") return t.orgGuidance;
    return t.consoleGuidance;
  }, [step, t]);

  async function saveEnterprise() {
    await api.saveEnterpriseSetup({
      enterprise_id: enterpriseID,
      enterprise_name: enterpriseName,
      admin_user_id: adminUserID,
      environment_label: environmentLabel
    });
    setStatus(t.saved);
    setStep("environment");
  }

  async function checkEnvironment() {
    await api.loadSetupEnvironment();
    setStatus(t.environmentReady);
    setStep("secrets");
  }

  async function validateSecrets() {
    const result = await api.validateSecretRefs({
      refs: {
        llmrouter_api_key: llmrouterRef,
        oa_token: oaRef,
        connector_credential: connectorRef
      }
    });
    setStatus(result.valid ? t.validated : t.unresolved);
    if (result.valid) {
      setStep("org");
    }
  }

  async function previewImport() {
    const result = await api.previewOrgImport({
      enterprise_id: enterpriseID,
      provider,
      base_url: baseURL,
      departments_path: departmentsPath,
      employees_path: employeesPath,
      token_ref: oaRef
    });
    setPreview(result);
    setStep("console");
  }

  async function confirmImport() {
    if (!preview) {
      return;
    }
    await api.confirmOrgImport({
      enterprise_id: enterpriseID,
      provider,
      snapshot_hash: preview.snapshot_hash,
      human_confirmation_id: "confirm_first_org_import"
    });
    await onComplete();
  }

  return (
    <main className="first-run-shell" lang={locale === "zh" ? "zh-CN" : "en"}>
      <section className="first-run-panel" aria-labelledby="first-run-title">
        <header className="first-run-head">
          <div>
            <p className="first-run-kicker">AgentNexus</p>
            <h1 id="first-run-title">{t.title}</h1>
            <p>{t.subtitle}</p>
          </div>
          <div className="first-run-env">
            <span>gateway-api ready</span>
            <span>secret://env/</span>
            {onOpenDemo ? (
              <button className="first-run-demo-button" type="button" onClick={onOpenDemo}>
                {t.demoDashboard}
              </button>
            ) : null}
            {onExitSetup ? (
              <button className="first-run-return-button" type="button" onClick={onExitSetup}>
                {returnConsoleLabel}
              </button>
            ) : null}
          </div>
        </header>

        <ol className="first-run-steps" aria-label={t.title}>
          {stepOrder.map((key, index) => (
            <li className={index === activeIndex ? "is-active" : index < activeIndex ? "is-complete" : ""} key={key}>
              <span>{index + 1}</span>
              <strong>{t.steps[key]}</strong>
            </li>
          ))}
        </ol>

        <div className="tenant-onboarding">
          <section className="tenant-step-panel">
            {step === "tenant" ? (
              <div className="tenant-step-content">
                <h2>{t.tenantTitle}</h2>
                <p>{t.tenantBody}</p>
                <div className="tenant-form-grid">
                  <label>
                    <span className="field-label-row">
                      {t.tenantID}
                      <em>{t.editableHint}</em>
                    </span>
                    <Input className="first-run-input" aria-label={t.tenantID} value={enterpriseID} onChange={(event) => setEnterpriseID(event.currentTarget.value)} />
                  </label>
                  <label>
                    <span className="field-label-row">
                      {t.tenantName}
                      <em>{t.editableHint}</em>
                    </span>
                    <Input className="first-run-input" aria-label={t.tenantName} value={enterpriseName} onChange={(event) => setEnterpriseName(event.currentTarget.value)} />
                  </label>
                  <label>
                    <span className="field-label-row">
                      {t.adminUserID}
                      <em>{t.editableHint}</em>
                    </span>
                    <Input className="first-run-input" aria-label={t.adminUserID} value={adminUserID} onChange={(event) => setAdminUserID(event.currentTarget.value)} />
                  </label>
                  <label>
                    <span className="field-label-row">
                      {t.environmentLabel}
                      <em>{t.editableHint}</em>
                    </span>
                    <Input className="first-run-input" aria-label={t.environmentLabel} value={environmentLabel} onChange={(event) => setEnvironmentLabel(event.currentTarget.value)} />
                  </label>
                </div>
                <Button type="button" className="primary-button" onClick={saveEnterprise}>
                  {t.saveTenant}
                </Button>
              </div>
            ) : null}

            {step === "environment" ? (
              <div className="tenant-step-content">
                <h2>{t.environmentTitle}</h2>
                <p>{t.environmentBody}</p>
                <div className="tenant-preview-summary">
                  <strong>gateway-api</strong>
                  <span>ready</span>
                </div>
                <Button type="button" className="primary-button" onClick={checkEnvironment}>
                  {t.recheckEnvironment}
                </Button>
              </div>
            ) : null}

            {step === "secrets" ? (
              <div className="tenant-step-content">
                <h2>{t.secretsTitle}</h2>
                <p>{t.secretsBody}</p>
                <div className="tenant-form-grid single">
                  <label>
                    {t.llmrouterRef}
                    <Input className="first-run-input" aria-label={t.llmrouterRef} value={llmrouterRef} onChange={(event) => setLLMRouterRef(event.currentTarget.value)} />
                  </label>
                  <label>
                    {t.oaRef}
                    <Input className="first-run-input" aria-label={t.oaRef} value={oaRef} onChange={(event) => setOARef(event.currentTarget.value)} />
                  </label>
                  <label>
                    {t.connectorRef}
                    <Input className="first-run-input" aria-label={t.connectorRef} value={connectorRef} onChange={(event) => setConnectorRef(event.currentTarget.value)} />
                  </label>
                </div>
                <Button type="button" className="primary-button" onClick={validateSecrets}>
                  {t.validateSecrets}
                </Button>
              </div>
            ) : null}

            {step === "org" ? (
              <div className="tenant-step-content">
                <h2>{t.orgTitle}</h2>
                <p>{t.orgBody}</p>
                <div className="tenant-form-grid">
                  <label>
                    {t.provider}
                    <select aria-label={t.provider} value={provider} onChange={(event) => setProvider(event.currentTarget.value)}>
                      <option value="oa_http">OA HTTP</option>
                      <option value="wecom">WeCom</option>
                      <option value="feishu">Feishu</option>
                      <option value="dingtalk">DingTalk</option>
                    </select>
                  </label>
                  <label>
                    {t.baseURL}
                    <Input className="first-run-input" aria-label={t.baseURL} value={baseURL} onChange={(event) => setBaseURL(event.currentTarget.value)} />
                  </label>
                  <label>
                    {t.departmentsPath}
                    <Input className="first-run-input" aria-label={t.departmentsPath} value={departmentsPath} onChange={(event) => setDepartmentsPath(event.currentTarget.value)} />
                  </label>
                  <label>
                    {t.employeesPath}
                    <Input className="first-run-input" aria-label={t.employeesPath} value={employeesPath} onChange={(event) => setEmployeesPath(event.currentTarget.value)} />
                  </label>
                </div>
                <Button type="button" className="primary-button" onClick={previewImport}>
                  {t.previewImport}
                </Button>
              </div>
            ) : null}

            {step === "console" && preview ? (
              <div className="tenant-step-content">
                <h2>{t.consoleTitle}</h2>
                <p>{t.consoleBody}</p>
                <div className="tenant-preview-summary">
                  <strong>{t.ready(preview.employee_count, preview.department_count, preview.membership_count)}</strong>
                  <span>{enterpriseName}</span>
                </div>
                <Button type="button" className="primary-button" onClick={confirmImport}>
                  {t.confirmImport}
                </Button>
              </div>
            ) : null}
          </section>

          <aside className="tenant-guidance" aria-label={t.guidanceTitle}>
            <h2>{t.guidanceTitle}</h2>
            <p>{guidance}</p>
            {status ? <div className="first-run-status">{status}</div> : null}
            <dl>
              <div>
                <dt>{t.tenantID}</dt>
                <dd>{enterpriseID}</dd>
              </div>
              <div>
                <dt>{t.tenantName}</dt>
                <dd>{enterpriseName}</dd>
              </div>
              <div>
                <dt>{t.environmentLabel}</dt>
                <dd>{environmentLabel}</dd>
              </div>
            </dl>
          </aside>
        </div>
      </section>
    </main>
  );
}
