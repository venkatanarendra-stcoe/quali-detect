-- CreateTable
CREATE TABLE "scm_workspace_link_settings" (
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "link_id" UUID NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "updated_by_user_id" UUID NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scm_workspace_link_settings_pkey" PRIMARY KEY ("workspace_id","link_id")
);

-- CreateIndex
CREATE INDEX "scm_workspace_link_settings_tenant_id_link_id_idx" ON "scm_workspace_link_settings"("tenant_id", "link_id");

-- AddForeignKey
ALTER TABLE "scm_workspace_link_settings" ADD CONSTRAINT "scm_workspace_link_settings_tenant_id_link_id_fkey" FOREIGN KEY ("tenant_id", "link_id") REFERENCES "scm_installation_links"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_workspace_link_settings" ADD CONSTRAINT "scm_workspace_link_settings_tenant_id_workspace_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;
