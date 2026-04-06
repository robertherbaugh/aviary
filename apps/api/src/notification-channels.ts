import { createHmac, randomBytes } from "node:crypto";
import nodemailer from "nodemailer";
import type PgBoss from "pg-boss";
import { DeliveryStatus, type NotificationChannelType, type PrismaClient } from "@aviary/db";

const NOTIFICATION_DELIVERY_QUEUE = "notification-delivery";

export type SmtpConfig = {
  host: string;
  port: number;
  user: string | null;
  pass: string | null;
  from: string;
};

export type NotificationDeliveryJob = {
  channelId: string;
  notificationId: string | null;
  message: string;
  attempt: number;
};

// ---------------------------------------------------------------------------
// Per-channel delivery implementations
// ---------------------------------------------------------------------------

export async function deliverEmail(to: string, message: string, smtp: SmtpConfig): Promise<void> {
  const auth =
    smtp.user && smtp.pass ? { user: smtp.user, pass: smtp.pass } : undefined;

  const transporter = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth
  });

  await transporter.sendMail({
    from: smtp.from,
    to,
    subject: "Aviary Alert Notification",
    text: message
  });
}

export async function deliverWebhook(
  url: string,
  secret: string | null,
  message: string
): Promise<void> {
  const body = JSON.stringify({ event: "alert.notification", message, timestamp: new Date().toISOString() });
  const headers: Record<string, string> = { "content-type": "application/json" };

  if (secret) {
    const sig = createHmac("sha256", secret).update(body).digest("hex");
    headers["x-aviary-signature"] = `sha256=${sig}`;
  }

  const response = await fetch(url, { method: "POST", headers, body });
  if (!response.ok) {
    throw new Error(`Webhook returned HTTP ${response.status}`);
  }
}

export async function deliverSlack(webhookUrl: string, message: string): Promise<void> {
  const body = JSON.stringify({ text: message });
  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body
  });
  if (!response.ok) {
    throw new Error(`Slack webhook returned HTTP ${response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Core delivery handler (called by queue worker)
// ---------------------------------------------------------------------------

export async function deliverNotification(
  prisma: PrismaClient,
  input: NotificationDeliveryJob,
  smtp: SmtpConfig
): Promise<void> {
  const channel = await prisma.notificationChannel.findUnique({
    where: { id: input.channelId }
  });

  if (!channel || !channel.enabled) {
    return;
  }

  let errorMessage: string | null = null;

  try {
    if (channel.type === "email") {
      await deliverEmail(channel.target, input.message, smtp);
    } else if (channel.type === "webhook") {
      await deliverWebhook(channel.target, channel.webhookSecret, input.message);
    } else if (channel.type === "slack") {
      await deliverSlack(channel.target, input.message);
    }
  } catch (error) {
    errorMessage = error instanceof Error ? error.message : "Unknown delivery error";
    throw error;
  } finally {
    const status: DeliveryStatus = errorMessage ? DeliveryStatus.failed : DeliveryStatus.success;
    await prisma.notificationDelivery.create({
      data: {
        channelId: input.channelId,
        notificationId: input.notificationId,
        status,
        message: input.message,
        errorMessage,
        attempt: input.attempt
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Dispatch: enqueue delivery jobs for all enabled channels
// ---------------------------------------------------------------------------

export async function dispatchToChannels(
  prisma: PrismaClient,
  boss: PgBoss,
  message: string,
  notificationId: string | null
): Promise<void> {
  const channels = await prisma.notificationChannel.findMany({
    where: { enabled: true }
  });

  for (const channel of channels) {
    const job: NotificationDeliveryJob = {
      channelId: channel.id,
      notificationId,
      message,
      attempt: 1
    };

    await boss.send(NOTIFICATION_DELIVERY_QUEUE, job, {
      retryLimit: channel.retryCount,
      retryDelay: channel.retryBackoffSec,
      retryBackoff: true
    });
  }
}

// ---------------------------------------------------------------------------
// Helper: generate a secure webhook secret
// ---------------------------------------------------------------------------

export function generateWebhookSecret(): string {
  return randomBytes(32).toString("hex");
}

// ---------------------------------------------------------------------------
// Shape returned by list/get endpoints
// ---------------------------------------------------------------------------

export type ChannelView = {
  id: string;
  name: string;
  type: NotificationChannelType;
  target: string;
  enabled: boolean;
  createdAt: Date;
  lastDeliveryAt: Date | null;
  lastDeliveryStatus: DeliveryStatus | null;
  recentDeliveries: Array<{
    id: string;
    status: DeliveryStatus;
    message: string;
    sentAt: Date;
  }>;
};

export async function toChannelView(
  prisma: PrismaClient,
  channelId: string
): Promise<ChannelView | null> {
  const channel = await prisma.notificationChannel.findUnique({
    where: { id: channelId },
    include: {
      deliveries: {
        orderBy: { sentAt: "desc" },
        take: 20
      }
    }
  });

  if (!channel) return null;

  const last = channel.deliveries[0] ?? null;

  return {
    id: channel.id,
    name: channel.name,
    type: channel.type,
    target: channel.target,
    enabled: channel.enabled,
    createdAt: channel.createdAt,
    lastDeliveryAt: last?.sentAt ?? null,
    lastDeliveryStatus: last?.status ?? null,
    recentDeliveries: channel.deliveries.map((d) => ({
      id: d.id,
      status: d.status,
      message: d.message,
      sentAt: d.sentAt
    }))
  };
}
