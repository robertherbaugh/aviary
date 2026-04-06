import type PgBoss from "pg-boss";
import { AlertBackendType, AlertOperator, AlertSeverity, PrismaClient } from "@aviary/db";
import { dispatchToChannels } from "./notification-channels.js";

export type ParsedMetricInput = {
  serverId: string;
  metric: string;
  value: number;
};

function compare(operator: AlertOperator, threshold: number, value: number): boolean {
  if (operator === "gt") return value > threshold;
  if (operator === "lt") return value < threshold;
  return value === threshold;
}

function severityLabel(severity: AlertSeverity): string {
  return severity.toUpperCase();
}

type AlertsBackendConfig = {
  type: AlertBackendType;
  webhookUrl: string | null;
  authHeader: string | null;
};

async function dispatchAlertNotification(
  backend: AlertsBackendConfig,
  payload: {
    alertId: string;
    serverId: string;
    metric: string;
    operator: AlertOperator;
    threshold: number;
    severity: AlertSeverity;
    value: number;
    message: string;
    triggeredAt: Date;
  }
) {
  if (backend.type !== AlertBackendType.webhook || !backend.webhookUrl) {
    return;
  }

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (backend.authHeader) {
    headers.authorization = backend.authHeader;
  }

  const response = await fetch(backend.webhookUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({
      event: "alert.triggered",
      alert: payload
    })
  });

  if (!response.ok) {
    throw new Error(`Webhook backend returned ${response.status}`);
  }
}

export async function evaluateAlertsForMetrics(
  prisma: PrismaClient,
  metrics: ParsedMetricInput[],
  boss?: PgBoss
) {
  if (metrics.length === 0) return;
  const config = await prisma.appConfig.findUnique({
    where: { id: "default" },
    select: {
      alertsBackendType: true,
      alertsBackendWebhookUrl: true,
      alertsBackendAuthHeader: true
    }
  });
  const backend: AlertsBackendConfig = {
    type: config?.alertsBackendType ?? AlertBackendType.database,
    webhookUrl: config?.alertsBackendWebhookUrl ?? null,
    authHeader: config?.alertsBackendAuthHeader ?? null
  };

  const grouped = new Map<string, ParsedMetricInput[]>();
  for (const m of metrics) {
    const key = m.serverId;
    const list = grouped.get(key) ?? [];
    list.push(m);
    grouped.set(key, list);
  }

  for (const [serverId, serverMetrics] of grouped) {
    const alerts = await prisma.alert.findMany({ where: { serverId } });

    for (const alert of alerts) {
      const metric = serverMetrics.find((item) => item.metric === alert.metric);
      if (!metric) continue;
      if (!compare(alert.operator, alert.threshold, metric.value)) continue;

      const message = `${severityLabel(alert.severity)} ${alert.metric}=${metric.value} ${alert.operator} ${alert.threshold}`;

      const [, createdNotification] = await prisma.$transaction([
        prisma.alert.update({
          where: { id: alert.id },
          data: { lastTriggeredAt: new Date() }
        }),
        prisma.notification.create({
          data: {
            alertId: alert.id,
            message
          }
        })
      ]);

      try {
        await dispatchAlertNotification(backend, {
          alertId: alert.id,
          serverId: alert.serverId,
          metric: alert.metric,
          operator: alert.operator,
          threshold: alert.threshold,
          severity: alert.severity,
          value: metric.value,
          message,
          triggeredAt: createdNotification.triggeredAt
        });
      } catch (error) {
        console.error("Failed to dispatch alert to backend", {
          alertId: alert.id,
          backend: backend.type,
          error: error instanceof Error ? error.message : "Unknown error"
        });
      }

      if (boss) {
        try {
          await dispatchToChannels(prisma, boss, message, createdNotification.id);
        } catch (error) {
          console.error("Failed to dispatch alert to notification channels", {
            alertId: alert.id,
            error: error instanceof Error ? error.message : "Unknown error"
          });
        }
      }
    }
  }
}
