import PgBoss from "pg-boss";
import { env } from "./env.js";

export const PLAYBOOK_QUEUE = "playbook-jobs";
export const CREDENTIAL_ROTATION_QUEUE = "credential-rotation";
export const NOTIFICATION_DELIVERY_QUEUE = "notification-delivery";

export async function createQueueClient() {
  const boss = new PgBoss({
    connectionString: env.DATABASE_URL,
    schema: env.PGBOSS_SCHEMA
  });

  await boss.start();
  await boss.createQueue(PLAYBOOK_QUEUE);
  await boss.createQueue(CREDENTIAL_ROTATION_QUEUE);
  await boss.createQueue(NOTIFICATION_DELIVERY_QUEUE);

  return boss;
}
