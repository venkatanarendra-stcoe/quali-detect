# QmentisAI Integration Architecture

## Design

Use provider adapters behind common capability contracts. Do not force every provider into identical behavior where the provider does not support it.

## Categories

- Source control: GitHub, GitLab, Bitbucket.
- AI coding tools: Cursor, Claude Code, Codex, Kiro.
- Ticketing: Jira, Linear.
- Collaboration: Slack, Microsoft Teams.
- Security tools: Semgrep, SonarQube, Snyk, Trivy, OWASP ZAP, Burp.
- Cloud: AWS, Azure, GCP.
- Secrets management: Vault and compatible systems.

## Adapter responsibilities

- Provider authentication.
- Credential validation and secure storage.
- Capability discovery.
- Webhook registration and signature verification.
- Event normalization.
- API rate-limit handling.
- Retry and error classification.
- Connection health.
- Disconnect and credential revocation.

## Provider-specific event delivery

Use provider-native webhooks where available. Otherwise use provider-supported local hooks, callbacks, polling or HTTP events. Verify actual capabilities and limitations before committing to an integration design.

## Security

- Encrypt credentials at rest.
- Restrict credential access to required services.
- Never log tokens or secret values.
- Verify webhook signatures.
- Apply replay protection and idempotency.
- Scope each integration to its tenant/workspace/repository as required.
