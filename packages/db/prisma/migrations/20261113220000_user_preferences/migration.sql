-- User preferences (module user-preferences, owner decision 2026-11-13): interface preferences of one user inside one tenant.
-- One row per membership (unique on tenant + user); no row means defaults. Version 1 stores the accent colour key.
-- The composite foreign key to the membership makes the row belong to a user of that same tenant.

-- CreateTable
CREATE TABLE "user_preferences" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "accent" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "user_preferences_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_preferences_tenant_id_user_id_key" ON "user_preferences"("tenant_id", "user_id");

-- AddForeignKey
ALTER TABLE "user_preferences" ADD CONSTRAINT "user_preferences_tenant_id_user_id_fkey" FOREIGN KEY ("tenant_id", "user_id") REFERENCES "tenant_memberships"("tenant_id", "user_id") ON DELETE CASCADE ON UPDATE CASCADE;
