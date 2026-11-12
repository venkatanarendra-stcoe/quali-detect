-- SPEC §18 (ADR-012): workspace-level source-control links.

-- CreateTable
CREATE TABLE "scm_workspace_links" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "link_id" UUID NOT NULL,
    "status" "scm_link_status" NOT NULL DEFAULT 'linked',
    "linked_by_user_id" UUID NOT NULL,
    "linked_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "unlinked_by_user_id" UUID,
    "unlinked_at" TIMESTAMPTZ(6),

    CONSTRAINT "scm_workspace_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scm_workspace_link_repositories" (
    "tenant_id" UUID NOT NULL,
    "workspace_link_id" UUID NOT NULL,
    "provider" "scm_provider" NOT NULL DEFAULT 'github',
    "external_repo_id" TEXT NOT NULL,
    "node_id" TEXT,
    "full_name" TEXT NOT NULL,
    "added_by_user_id" UUID NOT NULL,
    "added_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scm_workspace_link_repositories_pkey" PRIMARY KEY ("workspace_link_id","external_repo_id")
);

-- CreateTable
CREATE TABLE "tenant_integration_settings" (
    "tenant_id" UUID NOT NULL,
    "allow_workspace_linking" BOOLEAN NOT NULL DEFAULT true,
    "updated_by_user_id" UUID,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_integration_settings_pkey" PRIMARY KEY ("tenant_id")
);

-- CreateIndex
CREATE INDEX "scm_workspace_links_tenant_id_link_id_status_idx" ON "scm_workspace_links"("tenant_id", "link_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "scm_workspace_links_workspace_id_link_id_key" ON "scm_workspace_links"("workspace_id", "link_id");

-- CreateIndex
CREATE UNIQUE INDEX "scm_workspace_links_tenant_id_id_key" ON "scm_workspace_links"("tenant_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "scm_workspace_links_tenant_id_workspace_id_id_key" ON "scm_workspace_links"("tenant_id", "workspace_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "scm_workspace_link_repositories_tenant_id_provider_external_key" ON "scm_workspace_link_repositories"("tenant_id", "provider", "external_repo_id");

-- AddForeignKey
ALTER TABLE "scm_workspace_links" ADD CONSTRAINT "scm_workspace_links_tenant_id_workspace_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_workspace_links" ADD CONSTRAINT "scm_workspace_links_tenant_id_link_id_fkey" FOREIGN KEY ("tenant_id", "link_id") REFERENCES "scm_installation_links"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_workspace_link_repositories" ADD CONSTRAINT "scm_workspace_link_repositories_tenant_id_workspace_link_i_fkey" FOREIGN KEY ("tenant_id", "workspace_link_id") REFERENCES "scm_workspace_links"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_integration_settings" ADD CONSTRAINT "tenant_integration_settings_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Repositories reference the workspace link. Backfill (A10): one workspace link per (workspace, tenant link) that already has repositories.
ALTER TABLE "repositories" ADD COLUMN "workspace_link_id" UUID;

INSERT INTO "scm_workspace_links" ("id", "tenant_id", "workspace_id", "link_id", "status", "linked_by_user_id", "linked_at", "unlinked_by_user_id", "unlinked_at")
SELECT gen_random_uuid(), r."tenant_id", r."workspace_id", r."link_id", l."status", l."linked_by_user_id", l."linked_at", l."unlinked_by_user_id", l."unlinked_at"
FROM (SELECT DISTINCT "tenant_id", "workspace_id", "link_id" FROM "repositories") r
JOIN "scm_installation_links" l ON l."tenant_id" = r."tenant_id" AND l."id" = r."link_id";

UPDATE "repositories" r SET "workspace_link_id" = wl."id"
FROM "scm_workspace_links" wl
WHERE wl."tenant_id" = r."tenant_id" AND wl."workspace_id" = r."workspace_id" AND wl."link_id" = r."link_id";

-- Existing live repositories go on their workspace link's allow-list.
INSERT INTO "scm_workspace_link_repositories" ("tenant_id", "workspace_link_id", "provider", "external_repo_id", "node_id", "full_name", "added_by_user_id", "added_at")
SELECT r."tenant_id", r."workspace_link_id", r."provider", r."external_repo_id", r."node_id", r."full_name", r."connected_by_user_id", r."connected_at"
FROM "repositories" r WHERE r."status" <> 'disconnected';

ALTER TABLE "repositories" ALTER COLUMN "workspace_link_id" SET NOT NULL;

-- CreateIndex
CREATE INDEX "repositories_tenant_id_workspace_link_id_idx" ON "repositories"("tenant_id", "workspace_link_id");

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_tenant_id_workspace_id_workspace_link_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "workspace_link_id") REFERENCES "scm_workspace_links"("tenant_id", "workspace_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- The tenant-level scope list and the routing switch are replaced by the workspace link.
DROP TABLE "scm_installation_link_workspaces";

DROP TABLE "scm_workspace_link_settings";
