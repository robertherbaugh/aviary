-- CreateEnum
CREATE TYPE "NotificationChannelType" AS ENUM ('email', 'webhook', 'slack');

-- CreateEnum
CREATE TYPE "DeliveryStatus" AS ENUM ('pending', 'success', 'failed');

-- CreateTable
CREATE TABLE "notification_channels" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "NotificationChannelType" NOT NULL,
    "target" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "retry_count" INTEGER NOT NULL DEFAULT 3,
    "retry_backoff_sec" INTEGER NOT NULL DEFAULT 60,
    "webhook_secret" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "notification_channels_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_deliveries" (
    "id" TEXT NOT NULL,
    "channel_id" TEXT NOT NULL,
    "notification_id" TEXT,
    "status" "DeliveryStatus" NOT NULL DEFAULT 'pending',
    "message" TEXT NOT NULL,
    "error_message" TEXT,
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "sent_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "notification_deliveries_channel_id_sent_at_idx" ON "notification_deliveries"("channel_id", "sent_at");

-- CreateIndex
CREATE INDEX "notification_deliveries_status_idx" ON "notification_deliveries"("status");

-- AddForeignKey
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "notification_channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;
