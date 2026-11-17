-- SPEC scan-decisioning 7.2a (part B), ADR-013: the tenant's data-egress consent for an external LLM provider. One row per
-- tenant, created on the first change; absence means no consent. Additive: a new table only.

CREATE TABLE "tenant_llm_settings" (
    "tenant_id" UUID NOT NULL,
    "external_consent" BOOLEAN NOT NULL DEFAULT false,
    "updated_by_user_id" UUID,
    "consent_changed_at" TIMESTAMPTZ(6),
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_llm_settings_pkey" PRIMARY KEY ("tenant_id")
);

ALTER TABLE "tenant_llm_settings" ADD CONSTRAINT "tenant_llm_settings_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "tenant_llm_settings" ADD CONSTRAINT "tenant_llm_settings_updated_by_user_id_fkey" FOREIGN KEY ("updated_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
