-- GitHub integration data model (docs/modules/repositories-github/SPEC.md): installations, tenant links, repositories, webhook deliveries, normalized SCM events; outbox exchange/routing key.

-- CreateEnum
CREATE TYPE "scm_provider" AS ENUM ('github');

-- CreateEnum
CREATE TYPE "scm_installation_status" AS ENUM ('active', 'suspended', 'revoked');

-- CreateEnum
CREATE TYPE "scm_account_type" AS ENUM ('organization', 'user');

-- CreateEnum
CREATE TYPE "scm_repository_selection" AS ENUM ('all', 'selected');

-- CreateEnum
CREATE TYPE "scm_link_status" AS ENUM ('linked', 'unlinked');

-- CreateEnum
CREATE TYPE "repository_status" AS ENUM ('active', 'unavailable', 'disconnected');

-- CreateEnum
CREATE TYPE "scm_delivery_outcome" AS ENUM ('accepted', 'duplicate', 'ignored', 'unknown_installation', 'rejected_payload');

-- CreateEnum
CREATE TYPE "scm_event_kind" AS ENUM ('push', 'pull_request', 'repository', 'installation', 'installation_repositories');

-- AlterTable
ALTER TABLE "outbox_messages" ADD COLUMN     "exchange" TEXT,
ADD COLUMN     "routing_key" TEXT;

-- CreateTable
CREATE TABLE "scm_installations" (
    "id" UUID NOT NULL,
    "provider" "scm_provider" NOT NULL,
    "external_installation_id" TEXT NOT NULL,
    "account_external_id" TEXT NOT NULL,
    "account_login" TEXT NOT NULL,
    "account_type" "scm_account_type" NOT NULL,
    "repository_selection" "scm_repository_selection" NOT NULL,
    "permissions" JSONB NOT NULL DEFAULT '{}',
    "status" "scm_installation_status" NOT NULL DEFAULT 'active',
    "last_checked_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "scm_installations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scm_installation_links" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "installation_id" UUID NOT NULL,
    "status" "scm_link_status" NOT NULL DEFAULT 'linked',
    "linked_by_user_id" UUID NOT NULL,
    "linked_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "unlinked_by_user_id" UUID,
    "unlinked_at" TIMESTAMPTZ(6),

    CONSTRAINT "scm_installation_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scm_installation_link_workspaces" (
    "tenant_id" UUID NOT NULL,
    "link_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,

    CONSTRAINT "scm_installation_link_workspaces_pkey" PRIMARY KEY ("link_id","workspace_id")
);

-- CreateTable
CREATE TABLE "repositories" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "link_id" UUID NOT NULL,
    "provider" "scm_provider" NOT NULL,
    "external_repo_id" TEXT NOT NULL,
    "node_id" TEXT,
    "full_name" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "owner_login" TEXT NOT NULL,
    "html_url" TEXT,
    "visibility" TEXT NOT NULL DEFAULT 'private',
    "default_branch" TEXT,
    "description" TEXT,
    "display_name" TEXT,
    "owner_user_id" UUID,
    "status" "repository_status" NOT NULL DEFAULT 'active',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "archived" BOOLEAN NOT NULL DEFAULT false,
    "consecutive_sync_failures" INTEGER NOT NULL DEFAULT 0,
    "last_sync_error" TEXT,
    "last_synced_at" TIMESTAMPTZ(6),
    "last_event_at" TIMESTAMPTZ(6),
    "connected_by_user_id" UUID NOT NULL,
    "connected_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "disconnected_at" TIMESTAMPTZ(6),
    "disconnect_reason" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "repositories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "repository_group_access" (
    "tenant_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "group_id" UUID NOT NULL,

    CONSTRAINT "repository_group_access_pkey" PRIMARY KEY ("repository_id","group_id")
);

-- CreateTable
CREATE TABLE "scm_webhook_deliveries" (
    "id" UUID NOT NULL,
    "provider" "scm_provider" NOT NULL,
    "delivery_id" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "action" TEXT,
    "external_installation_id" TEXT,
    "tenant_id" UUID,
    "outcome" "scm_delivery_outcome" NOT NULL,
    "payload_sha256" TEXT NOT NULL,
    "received_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scm_webhook_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scm_events" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "repository_id" UUID,
    "delivery_id" TEXT NOT NULL,
    "kind" "scm_event_kind" NOT NULL,
    "normalized" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scm_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "scm_installations_provider_external_installation_id_key" ON "scm_installations"("provider", "external_installation_id");

-- CreateIndex
CREATE INDEX "scm_installation_links_installation_id_status_idx" ON "scm_installation_links"("installation_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "scm_installation_links_tenant_id_installation_id_key" ON "scm_installation_links"("tenant_id", "installation_id");

-- CreateIndex
CREATE UNIQUE INDEX "scm_installation_links_tenant_id_id_key" ON "scm_installation_links"("tenant_id", "id");

-- CreateIndex
CREATE INDEX "scm_installation_link_workspaces_tenant_id_workspace_id_idx" ON "scm_installation_link_workspaces"("tenant_id", "workspace_id");

-- CreateIndex
CREATE INDEX "repositories_tenant_id_workspace_id_status_idx" ON "repositories"("tenant_id", "workspace_id", "status");

-- CreateIndex
CREATE INDEX "repositories_tenant_id_link_id_idx" ON "repositories"("tenant_id", "link_id");

-- CreateIndex
CREATE INDEX "repositories_tenant_id_node_id_idx" ON "repositories"("tenant_id", "node_id");

-- CreateIndex
CREATE INDEX "repositories_status_last_synced_at_idx" ON "repositories"("status", "last_synced_at");

-- CreateIndex
CREATE UNIQUE INDEX "repositories_tenant_id_provider_external_repo_id_key" ON "repositories"("tenant_id", "provider", "external_repo_id");

-- CreateIndex
CREATE UNIQUE INDEX "repositories_tenant_id_id_key" ON "repositories"("tenant_id", "id");

-- CreateIndex
CREATE INDEX "repository_group_access_tenant_id_group_id_idx" ON "repository_group_access"("tenant_id", "group_id");

-- CreateIndex
CREATE INDEX "scm_webhook_deliveries_received_at_idx" ON "scm_webhook_deliveries"("received_at");

-- CreateIndex
CREATE INDEX "scm_webhook_deliveries_tenant_id_received_at_idx" ON "scm_webhook_deliveries"("tenant_id", "received_at");

-- CreateIndex
CREATE UNIQUE INDEX "scm_webhook_deliveries_provider_delivery_id_key" ON "scm_webhook_deliveries"("provider", "delivery_id");

-- CreateIndex
CREATE INDEX "scm_events_tenant_id_repository_id_created_at_idx" ON "scm_events"("tenant_id", "repository_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "scm_events_tenant_id_delivery_id_kind_key" ON "scm_events"("tenant_id", "delivery_id", "kind");

-- AddForeignKey
ALTER TABLE "scm_installation_links" ADD CONSTRAINT "scm_installation_links_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_installation_links" ADD CONSTRAINT "scm_installation_links_installation_id_fkey" FOREIGN KEY ("installation_id") REFERENCES "scm_installations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_installation_link_workspaces" ADD CONSTRAINT "scm_installation_link_workspaces_tenant_id_link_id_fkey" FOREIGN KEY ("tenant_id", "link_id") REFERENCES "scm_installation_links"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_installation_link_workspaces" ADD CONSTRAINT "scm_installation_link_workspaces_tenant_id_workspace_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_tenant_id_workspace_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_tenant_id_link_id_fkey" FOREIGN KEY ("tenant_id", "link_id") REFERENCES "scm_installation_links"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_group_access" ADD CONSTRAINT "repository_group_access_tenant_id_repository_id_fkey" FOREIGN KEY ("tenant_id", "repository_id") REFERENCES "repositories"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_group_access" ADD CONSTRAINT "repository_group_access_tenant_id_group_id_fkey" FOREIGN KEY ("tenant_id", "group_id") REFERENCES "groups"("tenant_id", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_events" ADD CONSTRAINT "scm_events_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scm_events" ADD CONSTRAINT "scm_events_tenant_id_repository_id_fkey" FOREIGN KEY ("tenant_id", "repository_id") REFERENCES "repositories"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- An installation belongs to at most ONE tenant at a time: only one `linked` link per installation.
CREATE UNIQUE INDEX "scm_installation_links_one_linked_per_installation" ON "scm_installation_links"("installation_id") WHERE "status" = 'linked';

ALTER TABLE "repositories" ADD CONSTRAINT "repositories_failures_check" CHECK ("consecutive_sync_failures" >= 0);
