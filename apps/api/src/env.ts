import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.string().default("development"),
  DATABASE_URL: z.string().min(1),
  MIGRATE_ON_STARTUP: z.string().default("true"),
  API_PORT: z.coerce.number().default(4000),
  API_GRPC_PORT: z.coerce.number().default(50051),
  JWT_SECRET: z.string().min(16),
  CREDENTIAL_ENCRYPTION_KEY: z.string().min(32),
  OIDC_ISSUER_URL: z.string().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().optional(),
  AVIARY_DOMAIN: z.string().optional(),
  LOCAL_BOOTSTRAP_ADMIN: z.string().default("true"),
  LOCAL_BOOTSTRAP_ADMIN_EMAIL: z.string().email().default("admin@example.com"),
  LOCAL_BOOTSTRAP_ADMIN_PASSWORD: z.string().min(8).default("change-me"),
  TOTP_ISSUER: z.string().min(1).default("Aviary"),
  WEBAUTHN_RP_ID: z.string().min(1).optional(),
  WEBAUTHN_RP_NAME: z.string().min(1).default("Aviary"),
  WEBAUTHN_ORIGIN: z.string().url().optional(),
  PGBOSS_SCHEMA: z.string().default("pgboss"),
  INTERNAL_API_TOKEN: z.string().default("internal-token"),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default("aviary@localhost")
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error(parsed.error.flatten());
  throw new Error("Invalid environment variables");
}

export const env = {
  ...parsed.data,
  localBootstrapEnabled: parsed.data.LOCAL_BOOTSTRAP_ADMIN === "true",
  migrateOnStartup: parsed.data.MIGRATE_ON_STARTUP === "true"
};
