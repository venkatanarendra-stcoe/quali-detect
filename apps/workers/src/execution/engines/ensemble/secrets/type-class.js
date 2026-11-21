import { SECRET_TYPE_CLASSES, severityOfSecretType } from "@qmentisai/shared";

/**
 * The platform type-class table of the Secrets scan type (docs/modules/scan-engines/SPEC.md 5.6.4, 5.7; table content Recommended, owner
 * review pending): both tools' rule ids and plugin types map to the common type classes of `SECRET_TYPE_CLASSES`. An id the table does not
 * know becomes `other` (its original id stays in the finding's `rule.id` and provenance). The class decides the merge key, the severity
 * (`severityOfSecretType`, never critical) and the fixed platform title: NO tool prose (a Gitleaks `Description`, a detect-secrets type
 * label) is ever used as a title, so a tool text can never carry a value into a finding.
 *
 * Rule ids are the ones seen in REAL Gitleaks 8.30.1 and detect-secrets 1.5.0 output on 2026-11-21 plus the documented default rule
 * families (`github-*`, `gitlab-*`, `slack-*`); the table is data, extended by a reviewed change and a bump of the ensemble version.
 */

/** Gitleaks default-rule ids to a class (exact ids). */
export const GITLEAKS_RULE_CLASS = Object.freeze({
  "aws-access-token": "aws_access_key",
  "private-key": "private_key",
  "stripe-access-token": "stripe_key",
  jwt: "jwt",
  "jwt-base64": "jwt",
  "generic-api-key": "generic_api_key",
});
/** Gitleaks rule families by id prefix (checked in order after the exact ids). */
export const GITLEAKS_PREFIX_CLASS = Object.freeze([
  ["github-", "github_token"],
  ["gitlab-", "gitlab_token"],
  ["slack-", "slack_token"],
]);

/** detect-secrets plugin types (the `type` of a result, 1.5.0) to a class. */
export const DETECT_SECRETS_TYPE_CLASS = Object.freeze({
  "AWS Access Key": "aws_access_key",
  "Azure Storage Account access key": "azure_storage_key",
  "Basic Auth Credentials": "basic_auth_url",
  "GitHub Token": "github_token",
  "GitLab Token": "gitlab_token",
  "JSON Web Token": "jwt",
  "Private Key": "private_key",
  "Secret Keyword": "password_assignment",
  "Slack Token": "slack_token",
  "Stripe Access Key": "stripe_key",
  "Base64 High Entropy String": "high_entropy_string",
  "Hex High Entropy String": "high_entropy_string",
});

/**
 * Every plugin type label of detect-secrets 1.5.0 (VERIFIED from the pinned image on 2026-11-21 with `get_mapping_from_secret_type_to_class`).
 * Only these labels become a rule id and a rule name: a label that is not on the list (a hostile or newer output) is `unknown`, never copied, so
 * a tool that put a value into its type label could not carry it into a finding.
 */
export const DETECT_SECRETS_KNOWN_TYPES = Object.freeze([
  "AWS Access Key",
  "Artifactory Credentials",
  "Azure Storage Account access key",
  "Base64 High Entropy String",
  "Basic Auth Credentials",
  "Cloudant Credentials",
  "Discord Bot Token",
  "GitHub Token",
  "GitLab Token",
  "Hex High Entropy String",
  "IBM COS HMAC Credentials",
  "IBM Cloud IAM Key",
  "JSON Web Token",
  "Mailchimp Access Key",
  "NPM tokens",
  "OpenAI Token",
  "Private Key",
  "Public IP (ipv4)",
  "PyPI Token",
  "Secret Keyword",
  "SendGrid API Key",
  "Slack Token",
  "SoftLayer Credentials",
  "Square OAuth Secret",
  "Stripe Access Key",
  "Telegram Bot Token",
  "Twilio API Key",
]);

/** The fixed, platform-owned title of each class (no value, no tool text). */
export const SECRET_TITLES = Object.freeze({
  private_key: "Hard-coded private key",
  aws_access_key: "Hard-coded AWS access key",
  gcp_service_account: "Hard-coded Google Cloud service account key",
  azure_storage_key: "Hard-coded Azure storage account key",
  github_token: "Hard-coded GitHub token",
  gitlab_token: "Hard-coded GitLab token",
  slack_token: "Hard-coded Slack token",
  stripe_key: "Hard-coded Stripe key",
  jwt: "Hard-coded JSON Web Token",
  basic_auth_url: "Hard-coded credentials in a URL or header",
  generic_api_key: "Possible hard-coded API key",
  high_entropy_string: "Possible hard-coded secret (high entropy string)",
  password_assignment: "Possible hard-coded password",
  other: "Possible hard-coded secret",
});

/** @param {unknown} ruleId a Gitleaks `RuleID` @returns {string} a member of `SECRET_TYPE_CLASSES` */
export function gitleaksTypeClass(ruleId) {
  if (typeof ruleId !== "string") return "other";
  if (Object.hasOwn(GITLEAKS_RULE_CLASS, ruleId)) return GITLEAKS_RULE_CLASS[ruleId];
  for (const [prefix, cls] of GITLEAKS_PREFIX_CLASS) if (ruleId.startsWith(prefix)) return cls;
  return "other";
}

/** @param {unknown} type a detect-secrets `type` @returns {string} a member of `SECRET_TYPE_CLASSES` */
export function detectSecretsTypeClass(type) {
  return typeof type === "string" && Object.hasOwn(DETECT_SECRETS_TYPE_CLASS, type)
    ? DETECT_SECRETS_TYPE_CLASS[type]
    : "other";
}

const GENERIC = new Set(["generic_api_key", "high_entropy_string", "other"]);

/**
 * The confidence of a secret finding (Recommended): a rule with a specific format is `high` for Gitleaks and `medium` for detect-secrets'
 * keyword and format plugins; the generic classes (entropy, keyword, unknown id) are `medium` for Gitleaks and `low` for detect-secrets.
 * @param {"gitleaks" | "detect-secrets"} toolId @param {string} typeClass
 * @returns {"low" | "medium" | "high"}
 */
export function secretConfidence(toolId, typeClass) {
  const generic = GENERIC.has(typeClass) || typeClass === "password_assignment";
  if (toolId === "gitleaks") return generic ? "medium" : "high";
  return generic ? "low" : "medium";
}

/**
 * The class, severity and title of a secret finding. Pure.
 * @param {"gitleaks" | "detect-secrets"} toolId @param {string} typeClass
 */
export function describeSecret(toolId, typeClass) {
  if (!SECRET_TYPE_CLASSES.includes(typeClass)) throw new TypeError("unknown secret type class");
  const confidence = secretConfidence(toolId, typeClass);
  const sev = severityOfSecretType(typeClass, confidence);
  return { typeClass, confidence, severity: sev.severity, severityAssumed: sev.assumed };
}
