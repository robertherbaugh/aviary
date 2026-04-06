import { beforeEach, describe, expect, it, vi } from "vitest";
import { RotationStatus } from "@aviary/db";

vi.mock("@aviary/db", () => ({
  RotationStatus: { pending: "pending", success: "success", failed: "failed" },
  PrismaClient: vi.fn(),
}));

vi.mock("./queue.js", () => ({
  CREDENTIAL_ROTATION_QUEUE: "credential-rotation",
}));

import { generateSshKeyPair, nextRotationDate, enqueueCredentialRotation } from "./credentials.js";
import { getKey } from "./crypto.js";

const ENC_KEY = getKey("test-encryption-key-for-unit-tests!!");

function makePrisma(overrides: Record<string, unknown> = {}) {
  return {
    credential: {
      findUniqueOrThrow: vi.fn().mockResolvedValue({
        id: "cred-1",
        type: "ssh_key",
        encryptedValue: "mock-encrypted",
        username: "ubuntu",
      }),
    },
    rotationHistory: {
      create: vi.fn().mockResolvedValue({ id: "hist-1", credentialId: "cred-1", status: "pending" }),
      update: vi.fn().mockResolvedValue({ id: "hist-1", credentialId: "cred-1", status: "pending", queueJobId: "q-1" }),
    },
    ...overrides,
  } as unknown as Parameters<typeof enqueueCredentialRotation>[0];
}

function makeBoss() {
  return {
    send: vi.fn().mockResolvedValue("q-1"),
  } as unknown as Parameters<typeof enqueueCredentialRotation>[1];
}

describe("generateSshKeyPair", () => {
  it("returns privateKeyPem and publicKeyPem strings", () => {
    const { privateKeyPem, publicKeyPem } = generateSshKeyPair();
    expect(privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(publicKeyPem).toContain("-----BEGIN PUBLIC KEY-----");
  });

  it("generates unique keypairs on each call", () => {
    const pair1 = generateSshKeyPair();
    const pair2 = generateSshKeyPair();
    expect(pair1.privateKeyPem).not.toBe(pair2.privateKeyPem);
    expect(pair1.publicKeyPem).not.toBe(pair2.publicKeyPem);
  });

  it("produces ed25519 keys", () => {
    const { privateKeyPem, publicKeyPem } = generateSshKeyPair();
    // Ed25519 PKCS8 private keys are short (~119 bytes) and public keys (SPKI) are ~120 bytes
    expect(privateKeyPem.length).toBeGreaterThan(50);
    expect(publicKeyPem.length).toBeGreaterThan(50);
  });
});

describe("nextRotationDate", () => {
  it("returns a date intervalDays in the future", () => {
    const before = Date.now();
    const result = nextRotationDate(30);
    const after = Date.now();

    const expectedMs = 30 * 24 * 60 * 60 * 1000;
    expect(result.getTime()).toBeGreaterThanOrEqual(before + expectedMs - 1000);
    expect(result.getTime()).toBeLessThanOrEqual(after + expectedMs + 1000);
  });

  it("handles 1-day interval", () => {
    const now = new Date();
    const result = nextRotationDate(1);
    const diffDays = (result.getTime() - now.getTime()) / (24 * 60 * 60 * 1000);
    expect(diffDays).toBeCloseTo(1, 0);
  });

  it("handles 365-day interval", () => {
    const now = new Date();
    const result = nextRotationDate(365);
    const diffDays = (result.getTime() - now.getTime()) / (24 * 60 * 60 * 1000);
    expect(diffDays).toBeCloseTo(365, 0);
  });
});

describe("enqueueCredentialRotation", () => {
  it("creates a RotationHistory record and sends to queue", async () => {
    const db = makePrisma();
    const boss = makeBoss();

    const result = await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1", "manual");

    expect(db.rotationHistory.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          credentialId: "cred-1",
          status: RotationStatus.pending,
          triggeredBy: "manual",
        }),
      })
    );
    expect(boss.send).toHaveBeenCalledWith(
      "credential-rotation",
      expect.objectContaining({
        rotationHistoryId: "hist-1",
        credentialId: "cred-1",
      })
    );
    expect(result).toMatchObject({ id: "hist-1" });
  });

  it("uses scheduled trigger when specified", async () => {
    const db = makePrisma();
    const boss = makeBoss();

    await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1", "scheduled");

    expect(db.rotationHistory.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ triggeredBy: "scheduled" }),
      })
    );
  });

  it("defaults to manual trigger", async () => {
    const db = makePrisma();
    const boss = makeBoss();

    await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1");

    expect(db.rotationHistory.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ triggeredBy: "manual" }),
      })
    );
  });

  it("stores queue job id on the history record", async () => {
    const db = makePrisma();
    const boss = makeBoss();
    (boss.send as ReturnType<typeof vi.fn>).mockResolvedValue("boss-xyz");

    await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1", "manual");

    expect(db.rotationHistory.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "hist-1" },
        data: { queueJobId: "boss-xyz" },
      })
    );
  });

  it("throws if credential is not ssh_key type", async () => {
    const db = makePrisma({
      credential: {
        findUniqueOrThrow: vi.fn().mockResolvedValue({
          id: "cred-pw",
          type: "password",
          encryptedValue: "x",
          username: "ubuntu",
        }),
      },
    });
    const boss = makeBoss();

    await expect(enqueueCredentialRotation(db, boss, ENC_KEY, "cred-pw")).rejects.toThrow(
      "Rotation is only supported for ssh_key credentials"
    );
  });

  it("includes encrypted new private key in queue payload", async () => {
    const db = makePrisma();
    const boss = makeBoss();

    await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1", "manual");

    const sendCall = (boss.send as ReturnType<typeof vi.fn>).mock.calls.at(0)!;
    expect(sendCall[1]).toHaveProperty("encryptedNewPrivateKey");
    expect(typeof sendCall[1].encryptedNewPrivateKey).toBe("string");
    expect(sendCall[1].encryptedNewPrivateKey).toMatch(/^[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/);
  });

  it("includes new public key PEM in queue payload", async () => {
    const db = makePrisma();
    const boss = makeBoss();

    await enqueueCredentialRotation(db, boss, ENC_KEY, "cred-1", "manual");

    const sendCall = (boss.send as ReturnType<typeof vi.fn>).mock.calls.at(0)!;
    expect(sendCall[1]).toHaveProperty("newPublicKeyPem");
    expect(sendCall[1].newPublicKeyPem).toContain("-----BEGIN PUBLIC KEY-----");
  });
});
