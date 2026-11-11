-- Transactional outbox and consumer idempotency (docs/architecture/WORKER_ARCHITECTURE.md).

-- CreateEnum
CREATE TYPE "outbox_status" AS ENUM ('pending', 'sent', 'dead');

-- CreateEnum
CREATE TYPE "processed_message_status" AS ENUM ('processing', 'done');

-- CreateTable
CREATE TABLE "outbox_messages" (
    "id" UUID NOT NULL,
    "tenant_id" UUID,
    "message_id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "queue" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "outbox_status" NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "available_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_error" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sent_at" TIMESTAMPTZ(6),

    CONSTRAINT "outbox_messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "processed_messages" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "consumer" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "message_id" TEXT NOT NULL,
    "status" "processed_message_status" NOT NULL DEFAULT 'processing',
    "claimed_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(6),

    CONSTRAINT "processed_messages_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "outbox_messages_status_available_at_idx" ON "outbox_messages"("status", "available_at");

-- CreateIndex
CREATE INDEX "outbox_messages_tenant_id_idx" ON "outbox_messages"("tenant_id");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_messages_message_id_queue_key" ON "outbox_messages"("message_id", "queue");

-- CreateIndex
CREATE INDEX "processed_messages_completed_at_idx" ON "processed_messages"("completed_at");

-- CreateIndex
CREATE UNIQUE INDEX "processed_messages_tenant_id_consumer_idempotency_key_key" ON "processed_messages"("tenant_id", "consumer", "idempotency_key");

-- AddForeignKey
ALTER TABLE "outbox_messages" ADD CONSTRAINT "outbox_messages_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "processed_messages" ADD CONSTRAINT "processed_messages_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


ALTER TABLE "outbox_messages" ADD CONSTRAINT "outbox_messages_attempts_check" CHECK ("attempts" >= 0);
-- The relay's hot path: pending rows that are due.
CREATE INDEX "outbox_messages_pending_due_idx" ON "outbox_messages"("available_at", "created_at") WHERE "status" = 'pending';
