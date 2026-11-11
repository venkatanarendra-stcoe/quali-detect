-- ADR-009: secret storage foundation (per-tenant wrapped data keys + encrypted secrets). No plaintext column exists.

-- CreateEnum
CREATE TYPE "data_key_status" AS ENUM ('active', 'retiring', 'retired');

-- CreateTable
CREATE TABLE "tenant_data_keys" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "wrapped_key" TEXT NOT NULL,
    "master_key_version" INTEGER NOT NULL,
    "status" "data_key_status" NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_data_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secrets" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "purpose" TEXT NOT NULL,
    "ciphertext" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "dek_version" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotated_at" TIMESTAMPTZ(6),
    "deleted_at" TIMESTAMPTZ(6),

    CONSTRAINT "secrets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "tenant_data_keys_tenant_id_status_idx" ON "tenant_data_keys"("tenant_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_data_keys_tenant_id_version_key" ON "tenant_data_keys"("tenant_id", "version");

-- CreateIndex
CREATE INDEX "secrets_tenant_id_purpose_idx" ON "secrets"("tenant_id", "purpose");

-- AddForeignKey
ALTER TABLE "tenant_data_keys" ADD CONSTRAINT "tenant_data_keys_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- At most one active data key per tenant (a rotation retires the old one in the same transaction).
CREATE UNIQUE INDEX "tenant_data_keys_one_active_per_tenant" ON "tenant_data_keys"("tenant_id") WHERE "status" = 'active';

ALTER TABLE "tenant_data_keys" ADD CONSTRAINT "tenant_data_keys_version_check" CHECK ("version" >= 1 AND "master_key_version" >= 1);
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_dek_version_check" CHECK ("dek_version" >= 1);
