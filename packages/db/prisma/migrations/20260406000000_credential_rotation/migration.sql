-- CreateEnum
CREATE TYPE "RotationStatus" AS ENUM ('pending', 'success', 'failed');

-- AlterTable credentials: add rotation fields
ALTER TABLE "credentials"
  ADD COLUMN "rotation_interval_days" INTEGER,
  ADD COLUMN "next_rotation_at"       TIMESTAMPTZ,
  ADD COLUMN "last_rotated_at"        TIMESTAMPTZ;

-- CreateIndex on credentials for scheduled rotation queries
CREATE INDEX "credentials_next_rotation_at_idx" ON "credentials"("next_rotation_at");

-- CreateTable rotation_history
CREATE TABLE "rotation_history" (
  "id"             TEXT         NOT NULL,
  "credential_id"  TEXT         NOT NULL,
  "status"         "RotationStatus" NOT NULL DEFAULT 'pending',
  "triggered_by"   TEXT         NOT NULL DEFAULT 'manual',
  "queue_job_id"   TEXT,
  "error_message"  TEXT,
  "started_at"     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  "completed_at"   TIMESTAMPTZ,

  CONSTRAINT "rotation_history_pkey" PRIMARY KEY ("id")
);

-- CreateIndex on rotation_history
CREATE INDEX "rotation_history_credential_id_started_at_idx" ON "rotation_history"("credential_id", "started_at");

-- AddForeignKey
ALTER TABLE "rotation_history"
  ADD CONSTRAINT "rotation_history_credential_id_fkey"
  FOREIGN KEY ("credential_id") REFERENCES "credentials"("id") ON DELETE CASCADE ON UPDATE CASCADE;
