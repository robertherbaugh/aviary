import { generateKeyPairSync } from "node:crypto";
import type PgBoss from "pg-boss";
import { PrismaClient, RotationStatus } from "@aviary/db";
import { encryptSecret } from "./crypto.js";
import { CREDENTIAL_ROTATION_QUEUE } from "./queue.js";

export type RotationTrigger = "manual" | "scheduled";

/**
 * Generate a new ed25519 SSH keypair.
 * Returns the private key in PKCS#8 PEM format (asyncssh can import this)
 * and the public key in SPKI PEM format.
 */
export function generateSshKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/**
 * Enqueue a credential rotation job.
 * Creates a RotationHistory record in `pending` state, sends the job to the
 * credential-rotation queue, and returns the rotation history entry.
 */
export async function enqueueCredentialRotation(
  db: PrismaClient,
  boss: PgBoss,
  encKey: Buffer,
  credentialId: string,
  triggeredBy: RotationTrigger = "manual"
) {
  const credential = await db.credential.findUniqueOrThrow({ where: { id: credentialId } });

  if (credential.type !== "ssh_key") {
    throw new Error("Rotation is only supported for ssh_key credentials");
  }

  const { privateKeyPem, publicKeyPem } = generateSshKeyPair();
  const encryptedNewPrivateKey = encryptSecret(privateKeyPem, encKey);

  const history = await db.rotationHistory.create({
    data: {
      credentialId,
      status: RotationStatus.pending,
      triggeredBy
    }
  });

  const queueJobId = await boss.send(CREDENTIAL_ROTATION_QUEUE, {
    rotationHistoryId: history.id,
    credentialId,
    encryptedNewPrivateKey,
    newPublicKeyPem: publicKeyPem
  });

  const updated = await db.rotationHistory.update({
    where: { id: history.id },
    data: { queueJobId }
  });

  return updated;
}

/**
 * Compute the next rotation date from today given an interval in days.
 */
export function nextRotationDate(intervalDays: number): Date {
  const d = new Date();
  d.setDate(d.getDate() + intervalDays);
  return d;
}
