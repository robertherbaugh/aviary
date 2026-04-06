-- CreateTable
CREATE TABLE "audit_events" (
    "id" TEXT NOT NULL,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "resource_id" TEXT,
    "before_state" JSONB,
    "after_state" JSONB,
    "ip" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "audit_events_actor_idx" ON "audit_events"("actor");

-- CreateIndex
CREATE INDEX "audit_events_action_idx" ON "audit_events"("action");

-- CreateIndex
CREATE INDEX "audit_events_resource_idx" ON "audit_events"("resource");

-- CreateIndex
CREATE INDEX "audit_events_timestamp_idx" ON "audit_events"("timestamp");
