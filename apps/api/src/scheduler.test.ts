import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockEnqueueCredentialRotation } = vi.hoisted(() => ({
  mockEnqueueCredentialRotation: vi.fn().mockResolvedValue({ id: "hist-1" }),
}));

vi.mock("@aviary/db", () => ({
  JobStatus: { queued: "queued" },
  TargetType: { server: "server", tag: "tag", all: "all" },
  PrismaClient: vi.fn(),
}));

vi.mock("./queue.js", () => ({
  PLAYBOOK_QUEUE: "playbook-jobs",
  CREDENTIAL_ROTATION_QUEUE: "credential-rotation",
}));

vi.mock("./credentials.js", () => ({
  enqueueCredentialRotation: mockEnqueueCredentialRotation,
  nextRotationDate: vi.fn().mockReturnValue(new Date()),
  generateSshKeyPair: vi.fn().mockReturnValue({ privateKeyPem: "priv", publicKeyPem: "pub" }),
}));

vi.mock("./crypto.js", () => ({
  getKey: vi.fn().mockReturnValue(Buffer.alloc(32)),
  encryptSecret: vi.fn().mockReturnValue("enc"),
  decryptSecret: vi.fn().mockReturnValue("plain"),
  sha256: vi.fn().mockReturnValue("hash"),
}));

vi.mock("./env.js", () => ({
  env: {
    CREDENTIAL_ENCRYPTION_KEY: "test-key-32-chars-long-exactly!!",
    DATABASE_URL: "postgresql://test",
    PGBOSS_SCHEMA: "pgboss",
    INTERNAL_API_TOKEN: "test-token",
  },
}));

import { startScheduler } from "./scheduler.js";

function makePrisma() {
  return {
    schedule: {
      findMany: vi.fn().mockResolvedValue([]),
      update: vi.fn().mockResolvedValue({}),
    },
    server: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    job: {
      create: vi.fn().mockResolvedValue({ id: "job-id" }),
      update: vi.fn().mockResolvedValue({}),
    },
    credential: {
      findMany: vi.fn().mockResolvedValue([]),
    },
  } as unknown as Parameters<typeof startScheduler>[0];
}

function makeBoss() {
  return {
    send: vi.fn().mockResolvedValue("queue-job-id"),
  } as unknown as Parameters<typeof startScheduler>[1];
}

const SCHEDULE_BASE = {
  id: "sched-1",
  enabled: true,
  playbookId: "pb-1",
  useSudo: false,
  cronExpression: "0 * * * *", // every hour
};

describe("startScheduler", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns a cleanup function", () => {
    const prisma = makePrisma();
    const boss = makeBoss();
    const cleanup = startScheduler(prisma, boss);
    expect(typeof cleanup).toBe("function");
    cleanup();
  });

  it("does not create jobs when there are no due schedules", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();
    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.job.create).not.toHaveBeenCalled();
    expect(boss.send).not.toHaveBeenCalled();
    cleanup();
  });

  it("creates a job and enqueues it for each resolved server", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "server", targetIds: ["srv-1"] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: "srv-1" }]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.job.create).toHaveBeenCalledOnce();
    expect(boss.send).toHaveBeenCalledOnce();
    expect(boss.send).toHaveBeenCalledWith(
      "playbook-jobs",
      expect.objectContaining({ jobId: "job-id", serverId: "srv-1" })
    );
    cleanup();
  });

  it("updates the schedule with lastRunAt and the next cron run time", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "server", targetIds: ["srv-1"] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: "srv-1" }]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.schedule.update).toHaveBeenCalledOnce();
    const updateCall = (prisma.schedule.update as ReturnType<typeof vi.fn>).mock.calls.at(0)![0] as {
      data: { lastRunAt: Date; nextRunAt: Date };
    };
    expect(updateCall.data.lastRunAt).toBeInstanceOf(Date);
    expect(updateCall.data.nextRunAt).toBeInstanceOf(Date);
    cleanup();
  });

  it("creates one job per server when multiple servers are resolved (targetType=all)", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "all", targetIds: [] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: "srv-a" },
      { id: "srv-b" },
    ]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.job.create).toHaveBeenCalledTimes(2);
    expect(boss.send).toHaveBeenCalledTimes(2);
    cleanup();
  });

  it("resolves servers by tag when targetType is tag", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "tag", targetIds: ["prod"] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: "srv-tagged" }]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.server.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ tags: { hasSome: ["prod"] } }),
      })
    );
    expect(prisma.job.create).toHaveBeenCalledOnce();
    cleanup();
  });

  it("filters to only active servers when resolving by id list", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "server", targetIds: ["srv-1", "srv-inactive"] },
    ]);
    // Only srv-1 is active
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: "srv-1" }]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.server.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ active: true }),
      })
    );
    expect(prisma.job.create).toHaveBeenCalledOnce();
    cleanup();
  });

  it("does nothing when a schedule has no matching active servers", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "server", targetIds: ["srv-gone"] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.job.create).not.toHaveBeenCalled();
    expect(boss.send).not.toHaveBeenCalled();
    // Schedule is still updated
    expect(prisma.schedule.update).toHaveBeenCalledOnce();
    cleanup();
  });

  it("stops polling after the cleanup function is called", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();
    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const cleanup = startScheduler(prisma, boss);
    cleanup();

    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.schedule.findMany).not.toHaveBeenCalled();
  });

  it("stores the queueJobId returned by pg-boss on the job record", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();
    (boss.send as ReturnType<typeof vi.fn>).mockResolvedValue("boss-job-xyz");

    (prisma.schedule.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { ...SCHEDULE_BASE, targetType: "server", targetIds: ["srv-1"] },
    ]);
    (prisma.server.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: "srv-1" }]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(prisma.job.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { queueJobId: "boss-job-xyz" } })
    );
    cleanup();
  });
});

describe("startScheduler — credential rotation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockEnqueueCredentialRotation.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not enqueue rotation when no credentials are due", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(mockEnqueueCredentialRotation).not.toHaveBeenCalled();
    cleanup();
  });

  it("enqueues rotation for each due ssh_key credential", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.credential.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: "cred-1", type: "ssh_key", rotationIntervalDays: 30 },
      { id: "cred-2", type: "ssh_key", rotationIntervalDays: 90 },
    ]);

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(mockEnqueueCredentialRotation).toHaveBeenCalledTimes(2);
    expect(mockEnqueueCredentialRotation).toHaveBeenCalledWith(
      prisma, boss, expect.any(Buffer), "cred-1", "scheduled"
    );
    expect(mockEnqueueCredentialRotation).toHaveBeenCalledWith(
      prisma, boss, expect.any(Buffer), "cred-2", "scheduled"
    );
    cleanup();
  });

  it("continues to process remaining credentials if one enqueue fails", async () => {
    const prisma = makePrisma();
    const boss = makeBoss();

    (prisma.credential.findMany as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: "cred-fail", type: "ssh_key", rotationIntervalDays: 30 },
      { id: "cred-ok", type: "ssh_key", rotationIntervalDays: 30 },
    ]);

    mockEnqueueCredentialRotation
      .mockRejectedValueOnce(new Error("queue unavailable"))
      .mockResolvedValueOnce({ id: "hist-2" });

    const cleanup = startScheduler(prisma, boss);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(mockEnqueueCredentialRotation).toHaveBeenCalledTimes(2);
    cleanup();
  });
});
