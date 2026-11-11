export const MODULE_NAME = "integrations";
export const API_PREFIX = "/api/v1";
export const OPENAPI_TAG = "Integrations";
/** The provider catalog (T-13). Only GitHub is live; the rest is listed so the UI never implies a capability that does not exist. */
export const CATALOG = Object.freeze([
  { provider: "github", name: "GitHub", category: "source_control", available: true },
  { provider: "gitlab", name: "GitLab", category: "source_control", available: false },
  { provider: "bitbucket", name: "Bitbucket", category: "source_control", available: false },
  { provider: "cursor", name: "Cursor", category: "ai_coding_tools", available: false, beta: true },
  {
    provider: "claude_code",
    name: "Claude Code",
    category: "ai_coding_tools",
    available: false,
    beta: true,
  },
  { provider: "codex", name: "Codex", category: "ai_coding_tools", available: false, beta: true },
  { provider: "kiro", name: "Kiro", category: "ai_coding_tools", available: false, beta: true },
  { provider: "jira", name: "Jira", category: "ticketing", available: false },
  { provider: "linear", name: "Linear", category: "ticketing", available: false },
  { provider: "slack", name: "Slack", category: "collaboration", available: false },
  {
    provider: "microsoft_teams",
    name: "Microsoft Teams",
    category: "collaboration",
    available: false,
  },
  { provider: "semgrep", name: "Semgrep", category: "security_tools", available: false },
  { provider: "sonarqube", name: "SonarQube", category: "security_tools", available: false },
  { provider: "snyk", name: "Snyk", category: "security_tools", available: false },
  { provider: "trivy", name: "Trivy", category: "security_tools", available: false },
  { provider: "owasp_zap", name: "OWASP ZAP", category: "security_tools", available: false },
  { provider: "burp", name: "Burp", category: "security_tools", available: false },
  { provider: "aws", name: "AWS", category: "cloud", available: false },
  { provider: "azure", name: "Azure", category: "cloud", available: false },
  { provider: "gcp", name: "GCP", category: "cloud", available: false },
  { provider: "vault", name: "Vault", category: "secrets", available: false },
]);
