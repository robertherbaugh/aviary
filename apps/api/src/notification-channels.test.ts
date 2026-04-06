import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("nodemailer", () => ({
  default: {
    createTransport: vi.fn().mockReturnValue({
      sendMail: vi.fn().mockResolvedValue({ messageId: "test-id" })
    })
  }
}));

vi.mock("@aviary/db", () => ({
  DeliveryStatus: { pending: "pending", success: "success", failed: "failed" }
}));

import nodemailer from "nodemailer";
import {
  deliverEmail,
  deliverNotification,
  deliverSlack,
  deliverWebhook,
  dispatchToChannels,
  generateWebhookSecret,
  toChannelView,
  type SmtpConfig
} from "./notification-channels.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SMTP: SmtpConfig = {
  host: "localhost",
  port: 1025,
  user: null,
  pass: null,
  from: "aviary@test.local"
};

function makePrisma(overrides: Record<string, unknown> = {}) {
  return {
    notificationChannel: {
      findUnique: vi.fn(),
      findMany: vi.fn().mockResolvedValue([]),
      ...((overrides.notificationChannel as object | undefined) ?? {})
    },
    notificationDelivery: {
      create: vi.fn().mockResolvedValue({}),
      ...((overrides.notificationDelivery as object | undefined) ?? {})
    }
  } as unknown as Parameters<typeof deliverNotification>[0];
}

function makeBoss() {
  return {
    send: vi.fn().mockResolvedValue("job-id")
  } as unknown as Parameters<typeof dispatchToChannels>[1];
}

// ---------------------------------------------------------------------------
// generateWebhookSecret
// ---------------------------------------------------------------------------

describe("generateWebhookSecret", () => {
  it("returns a 64-char hex string", () => {
    const secret = generateWebhookSecret();
    expect(secret).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(secret)).toBe(true);
  });

  it("returns different values each call", () => {
    expect(generateWebhookSecret()).not.toBe(generateWebhookSecret());
  });
});

// ---------------------------------------------------------------------------
// deliverEmail
// ---------------------------------------------------------------------------

describe("deliverEmail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates a transporter and sends mail", async () => {
    await deliverEmail("ops@example.com", "Alert: disk > 90%", SMTP);

    expect(nodemailer.createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ host: "localhost", port: 1025 })
    );

    const transport = (nodemailer.createTransport as ReturnType<typeof vi.fn>).mock.results[0]?.value as {
      sendMail: ReturnType<typeof vi.fn>;
    };
    expect(transport.sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        to: "ops@example.com",
        subject: "Aviary Alert Notification",
        text: "Alert: disk > 90%"
      })
    );
  });

  it("passes auth when user/pass are provided", async () => {
    await deliverEmail("ops@example.com", "msg", { ...SMTP, user: "u", pass: "p" });
    expect(nodemailer.createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ auth: { user: "u", pass: "p" } })
    );
  });

  it("omits auth when user is null", async () => {
    await deliverEmail("ops@example.com", "msg", { ...SMTP, user: null, pass: null });
    const call = (nodemailer.createTransport as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as {
      auth?: unknown;
    };
    expect(call.auth).toBeUndefined();
  });

  it("uses secure: true when port is 465", async () => {
    await deliverEmail("ops@example.com", "msg", { ...SMTP, port: 465 });
    expect(nodemailer.createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ secure: true })
    );
  });
});

// ---------------------------------------------------------------------------
// deliverWebhook
// ---------------------------------------------------------------------------

describe("deliverWebhook", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }));
  });

  it("posts JSON to the URL", async () => {
    await deliverWebhook("https://hooks.example.com/notify", null, "test msg");

    const [url, opts] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://hooks.example.com/notify");
    expect(opts.method).toBe("POST");

    const body = JSON.parse(opts.body as string) as { event: string; message: string };
    expect(body.event).toBe("alert.notification");
    expect(body.message).toBe("test msg");
  });

  it("includes HMAC signature when secret is provided", async () => {
    await deliverWebhook("https://hooks.example.com/notify", "mysecret", "test msg");

    const [, opts] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit & { headers: Record<string, string> }
    ];
    expect(opts.headers["x-aviary-signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it("omits signature header when secret is null", async () => {
    await deliverWebhook("https://hooks.example.com/notify", null, "test msg");

    const [, opts] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit & { headers: Record<string, string> }
    ];
    expect(opts.headers["x-aviary-signature"]).toBeUndefined();
  });

  it("throws when webhook returns non-OK status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
    await expect(deliverWebhook("https://hooks.example.com", null, "msg")).rejects.toThrow(
      "Webhook returned HTTP 503"
    );
  });
});

// ---------------------------------------------------------------------------
// deliverSlack
// ---------------------------------------------------------------------------

describe("deliverSlack", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }));
  });

  it("posts JSON with text field to slack URL", async () => {
    await deliverSlack("https://hooks.slack.com/services/T/B/xxx", "hello slack");

    const [url, opts] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://hooks.slack.com/services/T/B/xxx");
    const body = JSON.parse(opts.body as string) as { text: string };
    expect(body.text).toBe("hello slack");
  });

  it("throws when Slack returns non-OK status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 400 }));
    await expect(deliverSlack("https://hooks.slack.com/bad", "msg")).rejects.toThrow(
      "Slack webhook returned HTTP 400"
    );
  });
});

// ---------------------------------------------------------------------------
// deliverNotification
// ---------------------------------------------------------------------------

describe("deliverNotification", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }));
  });

  it("does nothing when channel is not found", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

    await deliverNotification(prisma, { channelId: "c1", notificationId: null, message: "msg", attempt: 1 }, SMTP);

    expect(prisma.notificationDelivery.create).not.toHaveBeenCalled();
  });

  it("does nothing when channel is disabled", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1", type: "webhook", target: "https://example.com", enabled: false, webhookSecret: null
    });

    await deliverNotification(prisma, { channelId: "c1", notificationId: null, message: "msg", attempt: 1 }, SMTP);

    expect(prisma.notificationDelivery.create).not.toHaveBeenCalled();
  });

  it("delivers via webhook and records success", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1", type: "webhook", target: "https://hooks.example.com/notify", enabled: true, webhookSecret: "sec"
    });

    await deliverNotification(prisma, { channelId: "c1", notificationId: "n1", message: "CRITICAL disk>90", attempt: 1 }, SMTP);

    expect(fetch).toHaveBeenCalled();
    expect(prisma.notificationDelivery.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          channelId: "c1",
          notificationId: "n1",
          status: "success",
          errorMessage: null
        })
      })
    );
  });

  it("delivers via slack and records success", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1", type: "slack", target: "https://hooks.slack.com/services/T/B/xxx", enabled: true, webhookSecret: null
    });

    await deliverNotification(prisma, { channelId: "c1", notificationId: null, message: "slack msg", attempt: 1 }, SMTP);

    const body = JSON.parse(
      ((fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit])[1].body as string
    ) as { text: string };
    expect(body.text).toBe("slack msg");
    expect(prisma.notificationDelivery.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: "success" }) })
    );
  });

  it("records failure and rethrows when delivery fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1", type: "webhook", target: "https://hooks.example.com/notify", enabled: true, webhookSecret: null
    });

    await expect(
      deliverNotification(prisma, { channelId: "c1", notificationId: null, message: "msg", attempt: 2 }, SMTP)
    ).rejects.toThrow();

    expect(prisma.notificationDelivery.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: "failed",
          attempt: 2
        })
      })
    );
  });

  it("delivers via email channel", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1", type: "email", target: "ops@example.com", enabled: true, webhookSecret: null
    });

    await deliverNotification(prisma, { channelId: "c1", notificationId: null, message: "email msg", attempt: 1 }, SMTP);

    expect(nodemailer.createTransport).toHaveBeenCalled();
    expect(prisma.notificationDelivery.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: "success" }) })
    );
  });
});

// ---------------------------------------------------------------------------
// dispatchToChannels
// ---------------------------------------------------------------------------

describe("dispatchToChannels", () => {
  it("enqueues one job per enabled channel with retry config", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.notificationChannel.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: "c1", retryCount: 3, retryBackoffSec: 60 },
      { id: "c2", retryCount: 5, retryBackoffSec: 30 }
    ]);

    await dispatchToChannels(prisma, boss, "CRITICAL disk full", "n1");

    expect(boss.send).toHaveBeenCalledTimes(2);

    const [queue1, job1, opts1] = (boss.send as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      unknown,
      { retryLimit: number; retryDelay: number; retryBackoff: boolean }
    ];
    expect(queue1).toBe("notification-delivery");
    expect((job1 as { channelId: string }).channelId).toBe("c1");
    expect(opts1.retryLimit).toBe(3);
    expect(opts1.retryBackoff).toBe(true);
  });

  it("does nothing when no channels exist", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();
    (prisma.notificationChannel.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    await dispatchToChannels(prisma, boss, "msg", null);

    expect(boss.send).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// toChannelView
// ---------------------------------------------------------------------------

describe("toChannelView", () => {
  it("returns null when channel not found", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

    const view = await toChannelView(prisma, "missing-id");
    expect(view).toBeNull();
  });

  it("maps channel with deliveries to view shape", async () => {
    const prisma = makePrisma();
    const sentAt = new Date("2026-01-01T00:00:00Z");
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1",
      name: "Ops Email",
      type: "email",
      target: "ops@example.com",
      enabled: true,
      createdAt: new Date("2026-01-01"),
      deliveries: [
        { id: "d1", status: "success", message: "CRITICAL cpu>90", sentAt }
      ]
    });

    const view = await toChannelView(prisma, "c1");

    expect(view).not.toBeNull();
    expect(view!.lastDeliveryAt).toBe(sentAt);
    expect(view!.lastDeliveryStatus).toBe("success");
    expect(view!.recentDeliveries).toHaveLength(1);
    expect(view!.recentDeliveries[0]!.id).toBe("d1");
  });

  it("sets lastDeliveryAt and lastDeliveryStatus to null when no deliveries", async () => {
    const prisma = makePrisma();
    (prisma.notificationChannel.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "c1",
      name: "Webhook",
      type: "webhook",
      target: "https://example.com",
      enabled: true,
      createdAt: new Date(),
      deliveries: []
    });

    const view = await toChannelView(prisma, "c1");

    expect(view!.lastDeliveryAt).toBeNull();
    expect(view!.lastDeliveryStatus).toBeNull();
    expect(view!.recentDeliveries).toHaveLength(0);
  });
});
