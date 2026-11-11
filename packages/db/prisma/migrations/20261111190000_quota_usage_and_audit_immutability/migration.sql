-- CreateTable
CREATE TABLE "tenant_quota_usage" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "quota_definition_id" UUID NOT NULL,
    "period_key" TEXT NOT NULL DEFAULT 'all',
    "used" BIGINT NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "tenant_quota_usage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "tenant_quota_usage_quota_definition_id_idx" ON "tenant_quota_usage"("quota_definition_id");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_quota_usage_tenant_id_quota_definition_id_period_key_key" ON "tenant_quota_usage"("tenant_id", "quota_definition_id", "period_key");

-- AddForeignKey
ALTER TABLE "tenant_quota_usage" ADD CONSTRAINT "tenant_quota_usage_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_quota_usage" ADD CONSTRAINT "tenant_quota_usage_quota_definition_id_fkey" FOREIGN KEY ("quota_definition_id") REFERENCES "quota_definitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Usage can never go negative.
ALTER TABLE "tenant_quota_usage" ADD CONSTRAINT "tenant_quota_usage_used_check" CHECK ("used" >= 0);

-- Audit logs are immutable: rows can only be inserted. UPDATE, DELETE and TRUNCATE are rejected for every role, including the
-- application's. (Consequence: a user or platform user with audit rows cannot be hard-deleted; they are deactivated instead.)
CREATE FUNCTION forbid_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed: audit logs are immutable', TG_OP, TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "audit_logs_immutable" BEFORE UPDATE OR DELETE ON "audit_logs" FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
CREATE TRIGGER "audit_logs_no_truncate" BEFORE TRUNCATE ON "audit_logs" FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation();
CREATE TRIGGER "platform_audit_logs_immutable" BEFORE UPDATE OR DELETE ON "platform_audit_logs" FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
CREATE TRIGGER "platform_audit_logs_no_truncate" BEFORE TRUNCATE ON "platform_audit_logs" FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation();
