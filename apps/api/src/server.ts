import { randomUUID } from "node:crypto";
import { z } from "zod";
import bcrypt from "bcryptjs";
import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import sensible from "@fastify/sensible";
import { CronExpressionParser } from "cron-parser";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
  type WebAuthnCredential
} from "@simplewebauthn/server";
import {
  AlertBackendType,
  AlertMetric,
  AlertOperator,
  AlertSeverity,
  CredentialType,
  JobStatus,
  Prisma,
  PrismaClient,
  TargetType,
  UserRole,
  prisma
} from "@aviary/db";
import {
  createAlertInputSchema,
  createCredentialInputSchema,
  createPlaybookInputSchema,
  createScheduleInputSchema,
  createServerInputSchema,
  updateServerInputSchema
} from "@aviary/types";
import { env } from "./env.js";
import { decryptSecret, encryptSecret, getKey, sha256 } from "./crypto.js";
import { signSessionToken, verifySessionToken } from "./auth.js";
import { evaluateAlertsForMetrics } from "./alerts.js";
import { createQueueClient, PLAYBOOK_QUEUE } from "./queue.js";
import { startScheduler } from "./scheduler.js";
import { buildTotpOtpauthUrl, generateTotpSecret, verifyTotpCode } from "./totp.js";
import { SERVER_WITH_CREDENTIAL_INCLUDE, toSafeServer } from "./servers.js";
import { intervalToCron, wizardAutomationInputSchema } from "./wizard.js";
import { startJobEventGrpcServer } from "./job-events-grpc.js";
import {
  JobEventBroker,
  listJobEventsAfter,
  parseCursorValue,
  toSseFrame,
  toSseHeartbeat
} from "./job-events.js";
import { extractAuditInfo, queryAuditEvents, writeAuditEvent } from "./audit.js";

const ENC_KEY = getKey(env.CREDENTIAL_ENCRYPTION_KEY);
const PUBLIC_ROUTES = new Set([
  "GET:/api/v1/auth/bootstrap-status",
  "POST:/api/v1/auth/local/bootstrap-setup",
  "POST:/api/v1/auth/oidc/login",
  "GET:/api/v1/auth/oidc/callback",
  "POST:/api/v1/auth/logout",
  "POST:/api/v1/auth/local/bootstrap-login",
  "POST:/api/v1/auth/webauthn/authenticate/options",
  "POST:/api/v1/auth/webauthn/authenticate/verify"
]);

function safeCredential(credential: { id: string; name: string; type: CredentialType; username: string; createdAt: Date }) {
  return {
    id: credential.id,
    name: credential.name,
    type: credential.type,
    username: credential.username,
    createdAt: credential.createdAt
  };
}

function parseOptionalDate(
  value: unknown,
  fieldName: string,
  badRequest: (message: string) => Error
): Date | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "string") {
    throw badRequest(`${fieldName} must be an ISO date string or null`);
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw badRequest(`${fieldName} is not a valid date`);
  }

  return parsed;
}

const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
type WebAuthnChallengeType = "registration" | "authentication";
type WebAuthnHeaderShape = {
  origin?: string | string[];
  host?: string | string[];
  "x-forwarded-host"?: string | string[];
  "x-forwarded-proto"?: string | string[];
};

type BootstrapSecurityConfigInput = {
  webauthnRpId?: string | null;
  webauthnRpName?: string | null;
  webauthnOrigin?: string | null;
  totpIssuer?: string | null;
};

type OidcRuntimeConfig = {
  oidcIssuerUrl: string | null;
  oidcClientId: string | null;
  oidcClientSecret: string | null;
  oidcRedirectUri: string | null;
};

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  if (!value) return undefined;
  const raw = Array.isArray(value) ? value[0] : value;
  if (!raw) return undefined;
  const first = raw.split(",")[0]?.trim();
  return first || undefined;
}

function hostToRpId(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith("[")) {
    const bracketEnd = trimmed.indexOf("]");
    if (bracketEnd > 1) {
      return trimmed.slice(1, bracketEnd);
    }
  }
  return trimmed.split(":")[0] ?? trimmed;
}

function normalizeOrigin(origin: string): string | undefined {
  try {
    return new URL(origin).origin;
  } catch {
    return undefined;
  }
}

function deriveOidcRedirectUriFromDomain(domain?: string): string | null {
  if (!domain?.trim()) return null;

  const trimmed = domain.trim();
  const scheme = env.NODE_ENV === "development" ? "http" : "https";
  const originCandidate = /^https?:\/\//i.test(trimmed) ? trimmed : `${scheme}://${trimmed}`;
  const origin = normalizeOrigin(originCandidate);
  if (!origin) return null;

  return new URL("/api/v1/auth/oidc/callback", `${origin}/`).toString();
}

function inferOriginFromHeaders(headers: WebAuthnHeaderShape): string | undefined {
  const directOrigin = firstHeaderValue(headers.origin);
  const normalizedDirectOrigin = directOrigin ? normalizeOrigin(directOrigin) : undefined;
  if (normalizedDirectOrigin) return normalizedDirectOrigin;

  const forwardedProto = firstHeaderValue(headers["x-forwarded-proto"]);
  const forwardedHost = firstHeaderValue(headers["x-forwarded-host"]);
  const host = forwardedHost ?? firstHeaderValue(headers.host);
  if (!host) return undefined;

  const scheme = forwardedProto || "http";
  return normalizeOrigin(`${scheme}://${host}`);
}

async function createWebAuthnChallenge(
  db: PrismaClient,
  input: { type: WebAuthnChallengeType; challenge: string; userId?: string; rpId?: string; origin?: string }
) {
  await db.webAuthnChallenge.deleteMany({
    where: {
      expiresAt: { lt: new Date() }
    }
  });

  return db.webAuthnChallenge.create({
    data: {
      type: input.type,
      challenge: input.challenge,
      userId: input.userId,
      rpId: input.rpId,
      origin: input.origin,
      expiresAt: new Date(Date.now() + WEBAUTHN_CHALLENGE_TTL_MS)
    }
  });
}

async function consumeWebAuthnChallenge(
  db: PrismaClient,
  input: { id: string; type: WebAuthnChallengeType; userId?: string }
) {
  const record = await db.webAuthnChallenge.findUnique({ where: { id: input.id } });
  if (!record || record.type !== input.type) {
    return null;
  }
  if (record.expiresAt < new Date()) {
    await db.webAuthnChallenge.deleteMany({ where: { id: record.id } });
    return null;
  }
  if (input.userId && record.userId !== input.userId) {
    return null;
  }

  await db.webAuthnChallenge.deleteMany({ where: { id: record.id } });
  return record;
}

function toWebAuthnCredential(record: {
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
}): WebAuthnCredential {
  return {
    id: record.credentialId,
    publicKey: Buffer.from(record.publicKey, "base64url"),
    counter: record.counter,
    transports: record.transports as AuthenticatorTransportFuture[]
  };
}

function scheduleNextRun(expression: string, fromDate: Date): Date {
  const interval = CronExpressionParser.parse(expression, { currentDate: fromDate });
  return interval.next().toDate();
}

async function resolveTargetServers(db: PrismaClient, targetType: TargetType, targetIds: string[]) {
  if (targetType === "all") {
    return db.server.findMany({ where: { active: true }, select: { id: true } });
  }

  if (targetType === "server") {
    return db.server.findMany({ where: { id: { in: targetIds }, active: true }, select: { id: true } });
  }

  return db.server.findMany({
    where: { active: true, tags: { hasSome: targetIds } },
    select: { id: true }
  });
}

export async function buildServer() {
  const app = Fastify({ logger: true });
  const db = prisma;
  const queue = await createQueueClient();
  const stopScheduler = startScheduler(db, queue);
  const jobEventBroker = new JobEventBroker();
  const grpcJobEventServer = await startJobEventGrpcServer({
    db,
    broker: jobEventBroker,
    internalToken: env.INTERNAL_API_TOKEN,
    port: env.API_GRPC_PORT,
    logger: app.log
  });

  app.addHook("onClose", async () => {
    stopScheduler();
    await grpcJobEventServer.close();
    await queue.stop();
    await db.$disconnect();
  });

  await app.register(cors, {
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "Last-Event-ID"]
  });
  await app.register(sensible);
  await app.register(rateLimit, {
    global: false
  });

  app.addHook("preHandler", async (request, reply) => {
    const routeUrl = request.routeOptions.url;
    if (!routeUrl) {
      return;
    }

    const key = `${request.method}:${routeUrl}`;
    if (!routeUrl.startsWith("/api/v1") || PUBLIC_ROUTES.has(key)) {
      return;
    }

    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      throw app.httpErrors.unauthorized("Missing bearer token");
    }

    const token = authorization.slice("Bearer ".length);
    let claims: Awaited<ReturnType<typeof verifySessionToken>>;
    try {
      claims = await verifySessionToken(env.JWT_SECRET, token);
    } catch {
      throw app.httpErrors.unauthorized("Invalid token");
    }

    const session = await db.session.findUnique({ where: { id: claims.sid } });
    if (!session || session.tokenHash !== sha256(token) || session.expiresAt < new Date()) {
      throw app.httpErrors.unauthorized("Session is invalid");
    }

    request.user = {
      id: claims.sub,
      role: claims.role,
      sessionId: claims.sid
    };
  });

  // Audit middleware: write an AuditEvent after every mutating API request
  app.addHook("onResponse", async (request) => {
    const method = request.method.toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return;

    const url = request.url;
    if (!url.startsWith("/api/v1/")) return;

    const routeUrl = request.routeOptions.url ?? url;
    const key = `${method}:${routeUrl}`;
    if (PUBLIC_ROUTES.has(key)) return;

    const actor = request.user?.id ?? "system";
    const ip =
      (request.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim() ??
      request.socket?.remoteAddress ??
      null;

    const info = extractAuditInfo(method, url);
    if (!info) return;

    writeAuditEvent(db, {
      actor,
      action: info.action,
      resource: info.resource,
      resourceId: info.resourceId,
      ip
    }).catch((err) => app.log.error({ err }, "Failed to write audit event"));
  });

  async function issueSession(user: { id: string; role: UserRole }) {
    const role = user.role === UserRole.admin ? "admin" : "operator";
    const sessionId = randomUUID();
    const token = await signSessionToken(env.JWT_SECRET, {
      sid: sessionId,
      sub: user.id,
      role
    });

    await db.session.create({
      data: {
        id: sessionId,
        user: {
          connect: { id: user.id }
        },
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000)
      }
    });

    return token;
  }

  async function resolveWebAuthnConfigOptional(
    headers: WebAuthnHeaderShape,
    config?: {
      webauthnOrigin: string | null;
      webauthnRpId: string | null;
      webauthnRpName: string | null;
    } | null
  ) {
    const appConfig = config ?? (await db.appConfig.findUnique({ where: { id: "default" } }));

    const configuredOrigin = appConfig?.webauthnOrigin ?? env.WEBAUTHN_ORIGIN;
    const inferredOrigin = inferOriginFromHeaders(headers);
    const origin = (configuredOrigin ? normalizeOrigin(configuredOrigin) : undefined) ?? inferredOrigin;

    const configuredRpId = appConfig?.webauthnRpId ?? env.WEBAUTHN_RP_ID;
    const headerHost = firstHeaderValue(headers["x-forwarded-host"]) ?? firstHeaderValue(headers.host);
    const rpId = configuredRpId ?? (origin ? new URL(origin).hostname : undefined) ?? (headerHost ? hostToRpId(headerHost) : undefined);

    const rpName = appConfig?.webauthnRpName ?? env.WEBAUTHN_RP_NAME;

    return { origin, rpId, rpName };
  }

  async function resolveWebAuthnConfig(headers: WebAuthnHeaderShape) {
    const resolved = await resolveWebAuthnConfigOptional(headers);
    const { origin, rpId } = resolved;

    if (!origin || !rpId) {
      throw app.httpErrors.badRequest(
        "Unable to resolve WebAuthn origin/rpId. Configure WEBAUTHN_* env vars or save values in app_config."
      );
    }

    return {
      ...resolved,
      origin,
      rpId
    };
  }

  async function resolveTotpIssuer(config?: { totpIssuer: string | null } | null): Promise<string> {
    const appConfig = config ?? (await db.appConfig.findUnique({ where: { id: "default" }, select: { totpIssuer: true } }));
    return appConfig?.totpIssuer?.trim() || env.TOTP_ISSUER;
  }

  async function resolveOidcRuntimeConfig(config?: OidcRuntimeConfig | null): Promise<OidcRuntimeConfig> {
    const appConfig =
      config ??
      (await db.appConfig.findUnique({
        where: { id: "default" },
        select: {
          oidcIssuerUrl: true,
          oidcClientId: true,
          oidcClientSecret: true,
          oidcRedirectUri: true
        }
      }));

    const configuredRedirectUri = appConfig?.oidcRedirectUri?.trim() || env.OIDC_REDIRECT_URI || null;
    const derivedRedirectUri = deriveOidcRedirectUriFromDomain(env.AVIARY_DOMAIN);

    return {
      oidcIssuerUrl: appConfig?.oidcIssuerUrl?.trim() || env.OIDC_ISSUER_URL || null,
      oidcClientId: appConfig?.oidcClientId?.trim() || env.OIDC_CLIENT_ID || null,
      oidcClientSecret: appConfig?.oidcClientSecret?.trim() || env.OIDC_CLIENT_SECRET || null,
      oidcRedirectUri: configuredRedirectUri ?? derivedRedirectUri
    };
  }

  function normalizeNullableText(value: string | null | undefined): string | null | undefined {
    if (value === undefined) return undefined;
    if (value === null) return null;
    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
  }

  app.get("/health", async () => ({ ok: true }));

  app.get("/api/v1/auth/bootstrap-status", async (request) => {
    const userCount = await db.user.count();
    const config = await db.appConfig.findUnique({
      where: { id: "default" },
      select: {
        webauthnRpId: true,
        webauthnRpName: true,
        webauthnOrigin: true,
        totpIssuer: true
      }
    });
    const defaults = await resolveWebAuthnConfigOptional(request.headers, config);
    const oidc = await resolveOidcRuntimeConfig();
    return {
      localBootstrapEnabled: env.localBootstrapEnabled,
      hasUsers: userCount > 0,
      setupRequired: env.localBootstrapEnabled && userCount === 0,
      bootstrapAdminEmail: env.LOCAL_BOOTSTRAP_ADMIN_EMAIL,
      oidcConfigured: Boolean(oidc.oidcIssuerUrl && oidc.oidcClientId && oidc.oidcRedirectUri),
      setupDefaults: {
        webauthnRpId: defaults.rpId ?? null,
        webauthnRpName: defaults.rpName,
        webauthnOrigin: defaults.origin ?? null,
        totpIssuer: await resolveTotpIssuer(config)
      }
    };
  });

  app.post("/api/v1/auth/local/bootstrap-setup", async (request) => {
    if (!env.localBootstrapEnabled) {
      throw app.httpErrors.forbidden("Bootstrap admin is disabled");
    }

    const body = request.body as { email: string; password: string; security?: BootstrapSecurityConfigInput };
    if (!body?.email || !body?.password) {
      throw app.httpErrors.badRequest("email and password are required");
    }

    const userCount = await db.user.count();
    if (userCount > 0) {
      throw app.httpErrors.conflict("Bootstrap setup is already complete");
    }

    const normalizedSecurity = body.security ?? {};
    const normalizedOriginInput = normalizeNullableText(normalizedSecurity.webauthnOrigin);
    const normalizedOrigin =
      normalizedOriginInput === undefined || normalizedOriginInput === null
        ? normalizedOriginInput
        : normalizeOrigin(normalizedOriginInput);
    if (normalizedOriginInput !== undefined && normalizedOriginInput !== null && !normalizedOrigin) {
      throw app.httpErrors.badRequest("security.webauthnOrigin must be a valid URL");
    }

    const normalizedRpId = normalizeNullableText(normalizedSecurity.webauthnRpId);
    const normalizedRpName = normalizeNullableText(normalizedSecurity.webauthnRpName);
    const normalizedTotpIssuer = normalizeNullableText(normalizedSecurity.totpIssuer);

    const inferred = await resolveWebAuthnConfigOptional(request.headers, null);
    const fallbackOrigin = normalizeOrigin(env.WEBAUTHN_ORIGIN ?? "");
    const finalOrigin = normalizedOrigin ?? fallbackOrigin ?? inferred.origin ?? null;
    const finalRpId =
      normalizedRpId ??
      env.WEBAUTHN_RP_ID ??
      (finalOrigin ? new URL(finalOrigin).hostname : null) ??
      inferred.rpId ??
      null;
    const finalRpName = normalizedRpName ?? env.WEBAUTHN_RP_NAME;
    const finalTotpIssuer = normalizedTotpIssuer ?? env.TOTP_ISSUER;

    const hashed = await bcrypt.hash(body.password, 12);
    const user = await db.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          email: body.email,
          passwordHash: hashed,
          role: UserRole.admin
        }
      });

      await tx.appConfig.upsert({
        where: { id: "default" },
        create: {
          id: "default",
          oidcEnabled: false,
          webauthnRpId: finalRpId,
          webauthnRpName: finalRpName,
          webauthnOrigin: finalOrigin,
          totpIssuer: finalTotpIssuer
        },
        update: {
          webauthnRpId: finalRpId,
          webauthnRpName: finalRpName,
          webauthnOrigin: finalOrigin,
          totpIssuer: finalTotpIssuer
        }
      });

      return created;
    });

    const token = await issueSession(user);
    return { token };
  });

  app.post("/api/v1/auth/local/bootstrap-login", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    if (!env.localBootstrapEnabled) {
      throw app.httpErrors.forbidden("Bootstrap admin is disabled");
    }

    const body = request.body as {
      email: string;
      password: string;
      totpCode?: string;
      webauthn?: {
        challengeId?: string;
        response?: AuthenticationResponseJSON;
      };
    };
    if (!body?.email || !body?.password) {
      throw app.httpErrors.badRequest("email and password are required");
    }

    const userCount = await db.user.count();
    let user = await db.user.findUnique({ where: { email: body.email } });

    if (!user) {
      if (userCount === 0) {
        const matchesEnvBootstrap =
          body.email === env.LOCAL_BOOTSTRAP_ADMIN_EMAIL &&
          body.password === env.LOCAL_BOOTSTRAP_ADMIN_PASSWORD;

        if (!matchesEnvBootstrap) {
          throw app.httpErrors.unauthorized(
            "No admin user exists yet. Complete bootstrap setup or sign in with configured bootstrap credentials."
          );
        }

        user = await db.user.create({
          data: {
            email: body.email,
            passwordHash: await bcrypt.hash(body.password, 12),
            role: UserRole.admin
          }
        });

        const config = await db.appConfig.findUnique({ where: { id: "default" } });
        if (!config) {
          const defaults = await resolveWebAuthnConfigOptional(request.headers, null);
          await db.appConfig.create({
            data: {
              id: "default",
              oidcEnabled: false,
              webauthnRpId: defaults.rpId ?? null,
              webauthnRpName: defaults.rpName,
              webauthnOrigin: defaults.origin ?? null,
              totpIssuer: env.TOTP_ISSUER
            }
          });
        }
      } else {
        throw app.httpErrors.unauthorized("Invalid credentials");
      }
    }

    if (!user.passwordHash) {
      throw app.httpErrors.unauthorized("Local login unavailable for this account");
    }

    const validPassword = await bcrypt.compare(body.password, user.passwordHash);
    if (!validPassword) {
      throw app.httpErrors.unauthorized("Invalid credentials");
    }

    if (user.totpEnabled) {
      if (!body.totpCode) {
        throw app.httpErrors.unauthorized("MFA code required");
      }

      if (!user.totpSecretEncrypted) {
        throw app.httpErrors.unauthorized("MFA secret is unavailable");
      }

      const secret = decryptSecret(user.totpSecretEncrypted, ENC_KEY);
      const validTotp = verifyTotpCode({ secret, code: body.totpCode });
      if (!validTotp) {
        throw app.httpErrors.unauthorized("Invalid MFA code");
      }
    }

    const userPasskeys = await db.webAuthnCredential.findMany({
      where: { userId: user.id },
      select: {
        id: true,
        credentialId: true,
        publicKey: true,
        counter: true,
        transports: true
      }
    });

    if (userPasskeys.length > 0) {
      const challengeId = body.webauthn?.challengeId;
      const response = body.webauthn?.response;

      if (!challengeId || !response) {
        const webauthnConfig = await resolveWebAuthnConfig(request.headers);
        const options = await generateAuthenticationOptions({
          rpID: webauthnConfig.rpId,
          userVerification: "required",
          allowCredentials: userPasskeys.map((credential) => ({
            id: credential.credentialId,
            transports: credential.transports as AuthenticatorTransportFuture[]
          }))
        });

        const challenge = await createWebAuthnChallenge(db, {
          type: "authentication",
          challenge: options.challenge,
          userId: user.id,
          rpId: webauthnConfig.rpId,
          origin: webauthnConfig.origin
        });

        return {
          mfaRequired: "webauthn" as const,
          challengeId: challenge.id,
          options
        };
      }

      const challenge = await consumeWebAuthnChallenge(db, {
        id: challengeId,
        type: "authentication",
        userId: user.id
      });
      if (!challenge) {
        throw app.httpErrors.unauthorized("WebAuthn challenge is invalid or expired");
      }

      const credentialId = response.id;
      if (!credentialId) {
        throw app.httpErrors.badRequest("Authentication response is missing credential id");
      }

      const passkey = await db.webAuthnCredential.findUnique({
        where: { credentialId }
      });
      if (!passkey || passkey.userId !== user.id) {
        throw app.httpErrors.unauthorized("Passkey not recognized for this account");
      }

      const webauthnConfig = await resolveWebAuthnConfig(request.headers);
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: challenge.origin ?? webauthnConfig.origin,
        expectedRPID: challenge.rpId ?? webauthnConfig.rpId,
        credential: toWebAuthnCredential(passkey),
        requireUserVerification: true
      });

      if (!verification.verified) {
        throw app.httpErrors.unauthorized("Passkey authentication verification failed");
      }

      await db.webAuthnCredential.update({
        where: { id: passkey.id },
        data: {
          counter: verification.authenticationInfo.newCounter,
          deviceType: verification.authenticationInfo.credentialDeviceType,
          backedUp: verification.authenticationInfo.credentialBackedUp,
          lastUsedAt: new Date()
        }
      });
    }

    const token = await issueSession(user);
    return { token };
  });

  app.post("/api/v1/auth/oidc/login", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async () => {
    const oidc = await resolveOidcRuntimeConfig();
    if (!oidc.oidcIssuerUrl || !oidc.oidcClientId || !oidc.oidcRedirectUri) {
      throw app.httpErrors.badRequest("OIDC configuration is incomplete");
    }

    const state = randomUUID();
    const authorizationUrl = new URL("authorize", oidc.oidcIssuerUrl).toString();
    const redirect = new URL(authorizationUrl);
    redirect.searchParams.set("response_type", "code");
    redirect.searchParams.set("client_id", oidc.oidcClientId);
    redirect.searchParams.set("redirect_uri", oidc.oidcRedirectUri);
    redirect.searchParams.set("scope", "openid profile email");
    redirect.searchParams.set("state", state);

    return { url: redirect.toString(), state };
  });

  app.get("/api/v1/auth/oidc/callback", async (request) => {
    const query = request.query as { code?: string };
    if (!query.code) {
      throw app.httpErrors.badRequest("Missing authorization code");
    }

    const user = await db.user.upsert({
      where: { oidcSubject: query.code },
      update: {},
      create: {
        oidcSubject: query.code,
        role: UserRole.operator
      }
    });

    const token = await issueSession(user);

    await db.appConfig.upsert({
      where: { id: "default" },
      create: { id: "default", oidcEnabled: true },
      update: { oidcEnabled: true }
    });

    return { token };
  });

  app.get("/api/v1/auth/session", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw app.httpErrors.notFound("User not found");

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      mfa: {
        totpEnabled: user.totpEnabled,
        pendingSetup: Boolean(user.totpPendingSecretEncrypted)
      }
    };
  });

  app.post("/api/v1/auth/logout", async (request) => {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      return { ok: true };
    }
    const token = authorization.slice("Bearer ".length);
    const claims = await verifySessionToken(env.JWT_SECRET, token);
    await db.session.deleteMany({ where: { id: claims.sid } });
    return { ok: true };
  });

  app.get("/api/v1/settings/oidc", async () => {
    const stored = await db.appConfig.findUnique({
      where: { id: "default" },
      select: {
        oidcIssuerUrl: true,
        oidcClientId: true,
        oidcClientSecret: true,
        oidcRedirectUri: true
      }
    });
    const effective = await resolveOidcRuntimeConfig(stored);

    return {
      stored: {
        issuerUrl: stored?.oidcIssuerUrl ?? null,
        clientId: stored?.oidcClientId ?? null,
        redirectUri: stored?.oidcRedirectUri ?? null,
        clientSecretConfigured: Boolean(stored?.oidcClientSecret)
      },
      effective: {
        issuerUrl: effective.oidcIssuerUrl,
        clientId: effective.oidcClientId,
        redirectUri: effective.oidcRedirectUri,
        configured: Boolean(effective.oidcIssuerUrl && effective.oidcClientId && effective.oidcRedirectUri)
      }
    };
  });

  app.put("/api/v1/settings/oidc", async (request) => {
    const body = request.body as {
      issuerUrl?: string | null;
      clientId?: string | null;
      clientSecret?: string | null;
      redirectUri?: string | null;
    };

    const normalizedIssuerUrl =
      body.issuerUrl === undefined ? undefined : normalizeNullableText(body.issuerUrl);
    const normalizedClientId =
      body.clientId === undefined ? undefined : normalizeNullableText(body.clientId);
    const normalizedClientSecret =
      body.clientSecret === undefined ? undefined : normalizeNullableText(body.clientSecret);
    const normalizedRedirectUri =
      body.redirectUri === undefined ? undefined : normalizeNullableText(body.redirectUri);

    if (normalizedIssuerUrl !== undefined && normalizedIssuerUrl !== null && !normalizeOrigin(normalizedIssuerUrl)) {
      throw app.httpErrors.badRequest("issuerUrl must be a valid URL");
    }
    if (normalizedRedirectUri !== undefined && normalizedRedirectUri !== null && !normalizeOrigin(normalizedRedirectUri)) {
      throw app.httpErrors.badRequest("redirectUri must be a valid URL");
    }

    const updated = await db.appConfig.upsert({
      where: { id: "default" },
      create: {
        id: "default",
        oidcEnabled: false,
        oidcIssuerUrl: normalizedIssuerUrl ?? null,
        oidcClientId: normalizedClientId ?? null,
        oidcClientSecret: normalizedClientSecret ?? null,
        oidcRedirectUri: normalizedRedirectUri ?? null
      },
      update: {
        oidcIssuerUrl: normalizedIssuerUrl,
        oidcClientId: normalizedClientId,
        oidcClientSecret: normalizedClientSecret,
        oidcRedirectUri: normalizedRedirectUri
      },
      select: {
        oidcIssuerUrl: true,
        oidcClientId: true,
        oidcClientSecret: true,
        oidcRedirectUri: true
      }
    });

    const effective = await resolveOidcRuntimeConfig(updated);
    return {
      stored: {
        issuerUrl: updated.oidcIssuerUrl,
        clientId: updated.oidcClientId,
        redirectUri: updated.oidcRedirectUri,
        clientSecretConfigured: Boolean(updated.oidcClientSecret)
      },
      effective: {
        issuerUrl: effective.oidcIssuerUrl,
        clientId: effective.oidcClientId,
        redirectUri: effective.oidcRedirectUri,
        configured: Boolean(effective.oidcIssuerUrl && effective.oidcClientId && effective.oidcRedirectUri)
      }
    };
  });

  app.get("/api/v1/settings/alerts-backend", async () => {
    const config = await db.appConfig.findUnique({
      where: { id: "default" },
      select: {
        alertsBackendType: true,
        alertsBackendWebhookUrl: true,
        alertsBackendAuthHeader: true
      }
    });

    return {
      stored: {
        type: config?.alertsBackendType ?? AlertBackendType.database,
        webhookUrl: config?.alertsBackendWebhookUrl ?? null,
        authHeaderConfigured: Boolean(config?.alertsBackendAuthHeader)
      },
      effective: {
        type: config?.alertsBackendType ?? AlertBackendType.database,
        webhookUrl: config?.alertsBackendWebhookUrl ?? null
      }
    };
  });

  app.put("/api/v1/settings/alerts-backend", async (request) => {
    const body = request.body as {
      type?: AlertBackendType;
      webhookUrl?: string | null;
      authHeader?: string | null;
    };

    const current = await db.appConfig.findUnique({
      where: { id: "default" },
      select: {
        alertsBackendType: true,
        alertsBackendWebhookUrl: true
      }
    });

    if (body.type !== undefined && !Object.values(AlertBackendType).includes(body.type)) {
      throw app.httpErrors.badRequest("type must be one of: database, webhook");
    }

    const normalizedWebhookUrl =
      body.webhookUrl === undefined
        ? undefined
        : body.webhookUrl === null || body.webhookUrl.trim() === ""
          ? null
          : body.webhookUrl.trim();
    const normalizedAuthHeader = body.authHeader === undefined ? undefined : normalizeNullableText(body.authHeader);

    if (normalizedWebhookUrl !== undefined && normalizedWebhookUrl !== null && !normalizeOrigin(normalizedWebhookUrl)) {
      throw app.httpErrors.badRequest("webhookUrl must be a valid URL");
    }

    const nextType = body.type ?? current?.alertsBackendType ?? AlertBackendType.database;
    const nextWebhookUrl = normalizedWebhookUrl ?? current?.alertsBackendWebhookUrl ?? null;

    if (nextType === AlertBackendType.webhook && !nextWebhookUrl) {
      throw app.httpErrors.badRequest("webhookUrl is required when type is webhook");
    }

    const updated = await db.appConfig.upsert({
      where: { id: "default" },
      create: {
        id: "default",
        oidcEnabled: false,
        alertsBackendType: nextType,
        alertsBackendWebhookUrl: nextWebhookUrl,
        alertsBackendAuthHeader: normalizedAuthHeader ?? null
      },
      update: {
        alertsBackendType: body.type,
        alertsBackendWebhookUrl: normalizedWebhookUrl,
        alertsBackendAuthHeader: normalizedAuthHeader
      },
      select: {
        alertsBackendType: true,
        alertsBackendWebhookUrl: true,
        alertsBackendAuthHeader: true
      }
    });

    return {
      stored: {
        type: updated.alertsBackendType,
        webhookUrl: updated.alertsBackendWebhookUrl,
        authHeaderConfigured: Boolean(updated.alertsBackendAuthHeader)
      },
      effective: {
        type: updated.alertsBackendType,
        webhookUrl: updated.alertsBackendWebhookUrl
      }
    };
  });

  app.get("/api/v1/auth/webauthn/config", async (request) => {
    const config = await db.appConfig.findUnique({ where: { id: "default" } });
    const effective = await resolveWebAuthnConfig(request.headers);

    return {
      stored: {
        rpId: config?.webauthnRpId ?? null,
        rpName: config?.webauthnRpName ?? null,
        origin: config?.webauthnOrigin ?? null
      },
      effective
    };
  });

  app.put("/api/v1/auth/webauthn/config", async (request) => {
    const body = request.body as { rpId?: string | null; rpName?: string | null; origin?: string | null };

    const normalizedOrigin =
      body.origin === undefined
        ? undefined
        : body.origin === null || body.origin.trim() === ""
          ? null
          : normalizeOrigin(body.origin.trim());

    if (body.origin !== undefined && body.origin !== null && body.origin.trim() !== "" && !normalizedOrigin) {
      throw app.httpErrors.badRequest("origin must be a valid URL");
    }

    const normalizedRpId =
      body.rpId === undefined
        ? undefined
        : body.rpId === null || body.rpId.trim() === ""
          ? null
          : body.rpId.trim();

    const normalizedRpName =
      body.rpName === undefined
        ? undefined
        : body.rpName === null || body.rpName.trim() === ""
          ? null
          : body.rpName.trim();

    const updated = await db.appConfig.upsert({
      where: { id: "default" },
      create: {
        id: "default",
        oidcEnabled: false,
        webauthnRpId: normalizedRpId ?? null,
        webauthnRpName: normalizedRpName ?? null,
        webauthnOrigin: normalizedOrigin ?? null
      },
      update: {
        webauthnRpId: normalizedRpId,
        webauthnRpName: normalizedRpName,
        webauthnOrigin: normalizedOrigin
      }
    });

    const effective = await resolveWebAuthnConfig(request.headers);
    return {
      stored: {
        rpId: updated.webauthnRpId,
        rpName: updated.webauthnRpName,
        origin: updated.webauthnOrigin
      },
      effective
    };
  });

  app.get("/api/v1/auth/webauthn/credentials", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const credentials = await db.webAuthnCredential.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" }
    });

    return credentials.map((credential) => ({
      id: credential.id,
      credentialId: credential.credentialId,
      transports: credential.transports,
      deviceType: credential.deviceType,
      backedUp: credential.backedUp,
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt
    }));
  });

  app.post("/api/v1/auth/webauthn/register/options", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw app.httpErrors.notFound("User not found");
    }

    const existingCredentials = await db.webAuthnCredential.findMany({
      where: { userId },
      select: {
        credentialId: true,
        transports: true
      }
    });

    const webauthnConfig = await resolveWebAuthnConfig(request.headers);

    const options = await generateRegistrationOptions({
      rpID: webauthnConfig.rpId,
      rpName: webauthnConfig.rpName,
      userID: new TextEncoder().encode(user.id),
      userName: user.email ?? user.id,
      userDisplayName: user.email ?? user.id,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required"
      },
      excludeCredentials: existingCredentials.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports as AuthenticatorTransportFuture[]
      }))
    });

    const challenge = await createWebAuthnChallenge(db, {
      type: "registration",
      challenge: options.challenge,
      userId,
      rpId: webauthnConfig.rpId,
      origin: webauthnConfig.origin
    });

    return {
      options,
      challengeId: challenge.id
    };
  });

  app.post("/api/v1/auth/webauthn/register/verify", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const body = request.body as {
      challengeId?: string;
      response?: RegistrationResponseJSON;
    };

    if (!body.challengeId || !body.response) {
      throw app.httpErrors.badRequest("challengeId and response are required");
    }

    const challenge = await consumeWebAuthnChallenge(db, {
      id: body.challengeId,
      type: "registration",
      userId
    });
    if (!challenge) {
      throw app.httpErrors.badRequest("Registration challenge is invalid or expired");
    }

    const webauthnConfig = await resolveWebAuthnConfig(request.headers);
    const verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin ?? webauthnConfig.origin,
      expectedRPID: challenge.rpId ?? webauthnConfig.rpId,
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw app.httpErrors.unauthorized("Passkey registration verification failed");
    }

    const credential = verification.registrationInfo.credential;
    const publicKey = Buffer.from(credential.publicKey).toString("base64url");
    const transports = (credential.transports ?? []).filter((transport) => typeof transport === "string");

    await db.webAuthnCredential.upsert({
      where: { credentialId: credential.id },
      update: {
        userId,
        publicKey,
        counter: credential.counter,
        transports,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        lastUsedAt: new Date()
      },
      create: {
        userId,
        credentialId: credential.id,
        publicKey,
        counter: credential.counter,
        transports,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        lastUsedAt: new Date()
      }
    });

    return { ok: true };
  });

  app.post("/api/v1/auth/webauthn/authenticate/options", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request) => {
    const body = request.body as { email?: string } | undefined;

    let challengeUserId: string | undefined;
    let allowCredentials:
      | Array<{
          id: string;
          transports?: AuthenticatorTransportFuture[];
        }>
      | undefined;

    if (body?.email) {
      const user = await db.user.findUnique({
        where: { email: body.email },
        select: {
          id: true
        }
      });

      if (user) {
        challengeUserId = user.id;
        const credentials = await db.webAuthnCredential.findMany({
          where: { userId: user.id },
          select: {
            credentialId: true,
            transports: true
          }
        });

        if (credentials.length > 0) {
          allowCredentials = credentials.map((credential) => ({
            id: credential.credentialId,
            transports: credential.transports as AuthenticatorTransportFuture[]
          }));
        }
      }
    }

    const webauthnConfig = await resolveWebAuthnConfig(request.headers);

    const options = await generateAuthenticationOptions({
      rpID: webauthnConfig.rpId,
      userVerification: "required",
      allowCredentials
    });

    const challenge = await createWebAuthnChallenge(db, {
      type: "authentication",
      challenge: options.challenge,
      userId: challengeUserId,
      rpId: webauthnConfig.rpId,
      origin: webauthnConfig.origin
    });

    return {
      options,
      challengeId: challenge.id
    };
  });

  app.post("/api/v1/auth/webauthn/authenticate/verify", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    const body = request.body as {
      challengeId?: string;
      response?: AuthenticationResponseJSON;
    };

    if (!body.challengeId || !body.response) {
      throw app.httpErrors.badRequest("challengeId and response are required");
    }

    const challenge = await consumeWebAuthnChallenge(db, {
      id: body.challengeId,
      type: "authentication"
    });
    if (!challenge) {
      throw app.httpErrors.badRequest("Authentication challenge is invalid or expired");
    }

    const credentialId = body.response.id;
    if (!credentialId) {
      throw app.httpErrors.badRequest("Authentication response is missing credential id");
    }

    const credential = await db.webAuthnCredential.findUnique({
      where: { credentialId },
      include: {
        user: true
      }
    });
    if (!credential) {
      throw app.httpErrors.unauthorized("Passkey not recognized");
    }

    if (challenge.userId && challenge.userId !== credential.userId) {
      throw app.httpErrors.unauthorized("Passkey does not match the requested account");
    }

    const webauthnConfig = await resolveWebAuthnConfig(request.headers);
    const verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin ?? webauthnConfig.origin,
      expectedRPID: challenge.rpId ?? webauthnConfig.rpId,
      credential: toWebAuthnCredential(credential),
      requireUserVerification: true
    });

    if (!verification.verified) {
      throw app.httpErrors.unauthorized("Passkey authentication verification failed");
    }

    await db.webAuthnCredential.update({
      where: { id: credential.id },
      data: {
        counter: verification.authenticationInfo.newCounter,
        deviceType: verification.authenticationInfo.credentialDeviceType,
        backedUp: verification.authenticationInfo.credentialBackedUp,
        lastUsedAt: new Date()
      }
    });

    const token = await issueSession(credential.user);
    return { token };
  });

  app.delete("/api/v1/auth/webauthn/credentials/:id", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const params = request.params as { id: string };
    await db.webAuthnCredential.deleteMany({
      where: {
        id: params.id,
        userId
      }
    });

    return { ok: true };
  });

  app.get("/api/v1/auth/mfa/status", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw app.httpErrors.notFound("User not found");

    return {
      totpEnabled: user.totpEnabled,
      pendingSetup: Boolean(user.totpPendingSecretEncrypted)
    };
  });

  app.post("/api/v1/auth/mfa/totp/setup", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw app.httpErrors.notFound("User not found");

    const secret = generateTotpSecret();
    const encryptedSecret = encryptSecret(secret, ENC_KEY);

    await db.user.update({
      where: { id: userId },
      data: {
        totpPendingSecretEncrypted: encryptedSecret
      }
    });

    return {
      secret,
      otpauthUrl: buildTotpOtpauthUrl({
        issuer: await resolveTotpIssuer(),
        accountName: user.email ?? user.id,
        secret
      })
    };
  });

  app.post("/api/v1/auth/mfa/totp/verify", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const body = request.body as { code?: string };
    if (!body.code) {
      throw app.httpErrors.badRequest("MFA code is required");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw app.httpErrors.notFound("User not found");
    if (!user.totpPendingSecretEncrypted) {
      throw app.httpErrors.badRequest("No pending TOTP setup");
    }

    const secret = decryptSecret(user.totpPendingSecretEncrypted, ENC_KEY);
    const valid = verifyTotpCode({ secret, code: body.code });
    if (!valid) {
      throw app.httpErrors.unauthorized("Invalid MFA code");
    }

    await db.user.update({
      where: { id: userId },
      data: {
        totpEnabled: true,
        totpSecretEncrypted: user.totpPendingSecretEncrypted,
        totpPendingSecretEncrypted: null
      }
    });

    return { ok: true };
  });

  app.post("/api/v1/auth/mfa/totp/disable", async (request) => {
    const userId = request.user?.id;
    if (!userId) {
      throw app.httpErrors.unauthorized("No active session");
    }

    const body = request.body as { code?: string };
    if (!body.code) {
      throw app.httpErrors.badRequest("MFA code is required");
    }

    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw app.httpErrors.notFound("User not found");
    if (!user.totpEnabled || !user.totpSecretEncrypted) {
      throw app.httpErrors.badRequest("TOTP is not enabled");
    }

    const secret = decryptSecret(user.totpSecretEncrypted, ENC_KEY);
    const valid = verifyTotpCode({ secret, code: body.code });
    if (!valid) {
      throw app.httpErrors.unauthorized("Invalid MFA code");
    }

    await db.user.update({
      where: { id: userId },
      data: {
        totpEnabled: false,
        totpSecretEncrypted: null,
        totpPendingSecretEncrypted: null
      }
    });

    return { ok: true };
  });

  app.get("/api/v1/servers", async () => {
    const servers = await db.server.findMany({ include: SERVER_WITH_CREDENTIAL_INCLUDE });
    return servers.map(toSafeServer);
  });

  app.post("/api/v1/servers", async (request) => {
    const body = createServerInputSchema.parse(request.body);
    const { credentialId, ...serverData } = body;

    const created = await db.$transaction(async (tx) => {
      const server = await tx.server.create({ data: serverData });

      if (credentialId) {
        await tx.serverCredential.create({
          data: {
            serverId: server.id,
            credentialId
          }
        });
      }

      return tx.server.findUniqueOrThrow({
        where: { id: server.id },
        include: SERVER_WITH_CREDENTIAL_INCLUDE
      });
    });

    return toSafeServer(created);
  });

  app.patch("/api/v1/servers/:id", async (request) => {
    const params = request.params as { id: string };
    const body = updateServerInputSchema.parse(request.body);
    const { credentialId, ...serverData } = body;

    const updated = await db.$transaction(async (tx) => {
      await tx.server.update({ where: { id: params.id }, data: serverData });

      if (credentialId !== undefined) {
        await tx.serverCredential.deleteMany({ where: { serverId: params.id } });
        if (credentialId) {
          await tx.serverCredential.create({
            data: {
              serverId: params.id,
              credentialId
            }
          });
        }
      }

      return tx.server.findUniqueOrThrow({
        where: { id: params.id },
        include: SERVER_WITH_CREDENTIAL_INCLUDE
      });
    });

    return toSafeServer(updated);
  });

  app.delete("/api/v1/servers/:id", async (request) => {
    const params = request.params as { id: string };
    await db.server.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.get("/api/v1/credentials", async () => {
    const rows = await db.credential.findMany();
    return rows.map(safeCredential);
  });

  app.post("/api/v1/credentials", async (request) => {
    const body = createCredentialInputSchema.parse(request.body);
    const credential = await db.credential.create({
      data: {
        name: body.name,
        type: body.type as CredentialType,
        username: body.username,
        encryptedValue: encryptSecret(body.secretValue, ENC_KEY)
      }
    });
    return safeCredential(credential);
  });

  app.patch("/api/v1/credentials/:id", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as {
      name?: string;
      username?: string;
      type?: CredentialType;
      secretValue?: string;
    };

    const updateData: Prisma.CredentialUpdateInput = {
      name: body.name,
      username: body.username,
      type: body.type
    };

    if (body.secretValue) {
      updateData.encryptedValue = encryptSecret(body.secretValue, ENC_KEY);
    }

    const updated = await db.credential.update({ where: { id: params.id }, data: updateData });
    return safeCredential(updated);
  });

  app.delete("/api/v1/credentials/:id", async (request) => {
    const params = request.params as { id: string };
    await db.credential.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.post("/api/v1/servers/:id/credentials", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as { credentialId: string };

    await db.serverCredential.deleteMany({ where: { serverId: params.id } });

    await db.serverCredential.create({
      data: {
        serverId: params.id,
        credentialId: body.credentialId
      }
    });

    return { ok: true };
  });

  app.delete("/api/v1/servers/:id/credentials/:credentialId", async (request) => {
    const params = request.params as { id: string; credentialId: string };

    await db.serverCredential.delete({
      where: {
        serverId_credentialId: {
          serverId: params.id,
          credentialId: params.credentialId
        }
      }
    });

    return { ok: true };
  });

  app.get("/api/v1/playbooks", async () => {
    const playbooks = await db.playbook.findMany({ include: { steps: { orderBy: { order: "asc" } } } });
    return playbooks;
  });

  app.get("/api/v1/playbooks/builtin", async () => {
    return db.playbook.findMany({ where: { isBuiltin: true }, include: { steps: { orderBy: { order: "asc" } } } });
  });

  app.post("/api/v1/playbooks", async (request) => {
    const body = createPlaybookInputSchema.parse(request.body);

    const playbook = await db.playbook.create({
      data: {
        name: body.name,
        description: body.description,
        isBuiltin: body.isBuiltin,
        useSudo: body.useSudo,
        createdBy: body.createdBy,
        stepsJson: body.steps as unknown as Prisma.JsonObject,
        steps: {
          createMany: {
            data: body.steps.map((step) => ({
              order: step.order,
              command: step.command,
              expectedExitCode: step.expectedExitCode,
              parseRule: step.parseRule
                ? (step.parseRule as Prisma.InputJsonValue)
                : Prisma.JsonNull
            }))
          }
        }
      },
      include: { steps: { orderBy: { order: "asc" } } }
    });

    return playbook;
  });

  app.patch("/api/v1/playbooks/:id", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as {
      name?: string;
      description?: string;
      useSudo?: boolean;
      steps?: Array<{ order: number; command: string; expectedExitCode: number; parseRule?: Record<string, unknown> }>;
    };

    const updated = await db.playbook.update({
      where: { id: params.id },
      data: {
        name: body.name,
        description: body.description,
        useSudo: body.useSudo,
        stepsJson: body.steps as unknown as Prisma.JsonObject
      }
    });

    if (body.steps) {
      await db.playbookStep.deleteMany({ where: { playbookId: params.id } });
      await db.playbookStep.createMany({
        data: body.steps.map((step) => ({
          playbookId: params.id,
          order: step.order,
          command: step.command,
          expectedExitCode: step.expectedExitCode,
          parseRule: step.parseRule
            ? (step.parseRule as Prisma.InputJsonValue)
            : Prisma.JsonNull
        }))
      });
    }

    return db.playbook.findUnique({ where: { id: updated.id }, include: { steps: true } });
  });

  app.delete("/api/v1/playbooks/:id", async (request) => {
    const params = request.params as { id: string };
    await db.playbook.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.post("/api/v1/wizard/automation", async (request) => {
    const body = wizardAutomationInputSchema.parse(request.body);
    const playbook = await db.playbook.findUnique({ where: { id: body.playbookId }, select: { id: true } });
    if (!playbook) {
      throw app.httpErrors.notFound("Selected playbook was not found.");
    }

    let cronExpression: string;
    try {
      cronExpression = intervalToCron({
        every: body.schedule.every,
        unit: body.schedule.unit
      });
    } catch (conversionError) {
      const message = conversionError instanceof Error ? conversionError.message : "Invalid schedule interval";
      throw app.httpErrors.badRequest(message);
    }

    const nextRunAt = scheduleNextRun(cronExpression, new Date());

    const created = await db.$transaction(async (tx) => {
      const credential =
        body.credential.mode === "existing"
          ? await tx.credential.findUnique({ where: { id: body.credential.id } })
          : await tx.credential.create({
              data: {
                name: body.credential.name,
                type: body.credential.type as CredentialType,
                username: body.credential.username,
                encryptedValue: encryptSecret(body.credential.secretValue, ENC_KEY)
              }
            });

      if (!credential) {
        throw app.httpErrors.notFound("Selected credential was not found.");
      }

      const serverId =
        body.server.mode === "existing"
          ? body.server.id
          : (
              await tx.server.create({
                data: {
                  displayName: body.server.displayName,
                  hostname: body.server.hostname,
                  ipAddress: body.server.ipAddress,
                  port: body.server.port,
                  username: body.server.username ?? null,
                  osType: body.server.osType ?? null,
                  tags: body.server.tags,
                  active: body.server.active
                }
              })
            ).id;

      const serverExists = await tx.server.findUnique({
        where: { id: serverId },
        select: { id: true }
      });
      if (!serverExists) {
        throw app.httpErrors.notFound("Selected server was not found.");
      }

      await tx.serverCredential.deleteMany({ where: { serverId } });
      await tx.serverCredential.create({
        data: {
          serverId,
          credentialId: credential.id
        }
      });

      const schedule = await tx.schedule.create({
        data: {
          playbookId: body.playbookId,
          targetType: TargetType.server,
          targetIds: [serverId],
          cronExpression,
          useSudo: body.schedule.useSudo,
          enabled: body.schedule.enabled,
          nextRunAt
        }
      });

      const safeServer = toSafeServer(
        await tx.server.findUniqueOrThrow({
          where: { id: serverId },
          include: SERVER_WITH_CREDENTIAL_INCLUDE
        })
      );

      return { credential, server: safeServer, schedule };
    });

    return {
      credential: safeCredential(created.credential),
      server: created.server,
      schedule: created.schedule
    };
  });

  app.get("/api/v1/schedules", async () => {
    return db.schedule.findMany({ include: { playbook: true } });
  });

  app.post("/api/v1/schedules", async (request) => {
    const body = createScheduleInputSchema.parse(request.body);
    const now = new Date();
    const next = scheduleNextRun(body.cronExpression, now);

    return db.schedule.create({
      data: {
        playbookId: body.playbookId,
        targetType: body.targetType as TargetType,
        targetIds: body.targetIds,
        cronExpression: body.cronExpression,
        useSudo: body.useSudo,
        enabled: body.enabled,
        nextRunAt: next
      }
    });
  });

  app.patch("/api/v1/schedules/:id", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as {
      playbookId?: string;
      targetType?: TargetType;
      targetIds?: string[];
      cronExpression?: string;
      useSudo?: boolean;
      enabled?: boolean;
    };

    const updateData: Prisma.ScheduleUpdateInput = {
      playbook: body.playbookId ? { connect: { id: body.playbookId } } : undefined,
      targetType: body.targetType,
      targetIds: body.targetIds,
      cronExpression: body.cronExpression,
      useSudo: body.useSudo,
      enabled: body.enabled
    };

    if (body.cronExpression) {
      updateData.nextRunAt = scheduleNextRun(body.cronExpression, new Date());
    }

    return db.schedule.update({ where: { id: params.id }, data: updateData });
  });

  app.delete("/api/v1/schedules/:id", async (request) => {
    const params = request.params as { id: string };
    await db.schedule.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.post("/api/v1/jobs/run-now", async (request) => {
    const body = request.body as {
      playbookId: string;
      targetType: TargetType;
      targetIds: string[];
      useSudo?: boolean;
    };
    const playbook = await db.playbook.findUnique({
      where: { id: body.playbookId },
      select: { id: true, useSudo: true }
    });
    if (!playbook) {
      throw app.httpErrors.notFound("Playbook not found");
    }
    const effectiveUseSudo = body.useSudo ?? playbook.useSudo;

    const servers = await resolveTargetServers(db, body.targetType, body.targetIds);
    const jobs = [];

    for (const server of servers) {
      const job = await db.job.create({
        data: {
          playbookId: body.playbookId,
          serverId: server.id,
          useSudo: effectiveUseSudo,
          status: JobStatus.queued
        }
      });

      const queueJobId = await queue.send(PLAYBOOK_QUEUE, {
        jobId: job.id,
        playbookId: body.playbookId,
        serverId: server.id,
        useSudo: effectiveUseSudo
      });

      const updated = await db.job.update({
        where: { id: job.id },
        data: { queueJobId }
      });

      jobs.push(updated);
    }

    return { count: jobs.length, jobs };
  });

  app.get("/api/v1/jobs", async (request) => {
    const query = request.query as {
      status?: JobStatus;
      serverId?: string;
      from?: string;
      to?: string;
      limit?: string;
      offset?: string;
    };

    const limit = Math.min(Number(query.limit ?? 50), 200);
    const offset = Number(query.offset ?? 0);

    const where: Prisma.JobWhereInput = {
      status: query.status,
      serverId: query.serverId
    };

    if (query.from || query.to) {
      where.enqueuedAt = {
        gte: query.from ? new Date(query.from) : undefined,
        lte: query.to ? new Date(query.to) : undefined
      };
    }

    return db.job.findMany({
      where,
      include: {
        server: true,
        playbook: true,
        schedule: true
      },
      orderBy: { enqueuedAt: "desc" },
      take: limit,
      skip: offset
    });
  });

  app.patch("/api/v1/jobs/:id", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as {
      status?: JobStatus;
      startedAt?: string | null;
      completedAt?: string | null;
    };

    if (!body || Object.keys(body).length === 0) {
      throw app.httpErrors.badRequest("At least one field is required");
    }

    if (body.status && !Object.values(JobStatus).includes(body.status)) {
      throw app.httpErrors.badRequest("Invalid job status");
    }

    const startedAt = parseOptionalDate(body.startedAt, "startedAt", (message) => app.httpErrors.badRequest(message));
    const completedAt = parseOptionalDate(body.completedAt, "completedAt", (message) =>
      app.httpErrors.badRequest(message)
    );

    return db.job.update({
      where: { id: params.id },
      data: {
        status: body.status,
        startedAt,
        completedAt
      },
      include: {
        server: true,
        playbook: true,
        schedule: true
      }
    });
  });

  app.delete("/api/v1/jobs/:id", async (request) => {
    const params = request.params as { id: string };

    const job = await db.job.findUnique({
      where: { id: params.id },
      select: { status: true }
    });

    if (!job) {
      throw app.httpErrors.notFound("Job not found");
    }

    if (job.status === JobStatus.queued || job.status === JobStatus.running) {
      throw app.httpErrors.conflict("Active jobs cannot be deleted");
    }

    await db.job.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.get("/api/v1/jobs/:id", async (request) => {
    const params = request.params as { id: string };
    return db.job.findUnique({
      where: { id: params.id },
      include: {
        server: true,
        playbook: true,
        schedule: true
      }
    });
  });

  app.get("/api/v1/jobs/:id/results", async (request) => {
    const params = request.params as { id: string };
    return db.jobResult.findMany({ where: { jobId: params.id }, orderBy: { stepOrder: "asc" } });
  });

  app.get("/api/v1/jobs/:id/events/stream", async (request, reply) => {
    const params = request.params as { id: string };
    const query = request.query as { cursor?: string };

    const job = await db.job.findUnique({ where: { id: params.id }, select: { id: true } });
    if (!job) {
      throw app.httpErrors.notFound("Job not found");
    }

    const rawLastEventId = request.headers["last-event-id"];
    const lastEventIdHeader = Array.isArray(rawLastEventId) ? rawLastEventId[0] : rawLastEventId;

    const cursorFromQuery = parseCursorValue(query.cursor);
    const cursorFromHeader = parseCursorValue(lastEventIdHeader);
    const afterSeq = cursorFromQuery ?? cursorFromHeader ?? 0;

    reply.hijack();
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no"
    });

    const replayEvents = await listJobEventsAfter(db, {
      jobId: params.id,
      afterSeq,
      limit: 1_000
    });

    for (const event of replayEvents) {
      reply.raw.write(toSseFrame(event));
    }

    reply.raw.write(toSseHeartbeat());

    let closed = false;
    const unsubscribe = jobEventBroker.subscribe(params.id, (event) => {
      if (closed || reply.raw.destroyed) {
        return;
      }
      reply.raw.write(toSseFrame(event));
    });

    const heartbeat = setInterval(() => {
      if (closed || reply.raw.destroyed) {
        return;
      }
      reply.raw.write(toSseHeartbeat());
    }, 15_000);

    const cleanup = () => {
      if (closed) {
        return;
      }
      closed = true;
      clearInterval(heartbeat);
      unsubscribe();
    };

    request.raw.on("close", cleanup);
    request.raw.on("error", cleanup);
  });

  app.get("/api/v1/alerts", async (request) => {
    const query = request.query as { unresolved?: string };
    const unresolvedOnly = query.unresolved === "true";

    const alerts = await db.alert.findMany({
      include: {
        notifications: {
          where: unresolvedOnly ? { acknowledged: false } : undefined,
          orderBy: { triggeredAt: "desc" },
          take: 20
        },
        server: true
      }
    });

    if (!unresolvedOnly) return alerts;

    return alerts.filter((alert) => alert.notifications.some((n) => !n.acknowledged));
  });

  app.post("/api/v1/alerts", async (request) => {
    const body = createAlertInputSchema.parse(request.body);
    return db.alert.create({
      data: {
        serverId: body.serverId,
        metric: body.metric as AlertMetric,
        threshold: body.threshold,
        operator: body.operator as AlertOperator,
        severity: body.severity as AlertSeverity,
        notificationChannel: body.notificationChannel
      }
    });
  });

  app.patch("/api/v1/alerts/:id", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as {
      metric?: AlertMetric;
      threshold?: number;
      operator?: AlertOperator;
      severity?: AlertSeverity;
      notificationChannel?: string;
    };

    return db.alert.update({ where: { id: params.id }, data: body });
  });

  app.delete("/api/v1/alerts/:id", async (request) => {
    const params = request.params as { id: string };
    await db.alert.delete({ where: { id: params.id } });
    return { ok: true };
  });

  app.post("/api/v1/alerts/:id/acknowledge", async (request) => {
    const params = request.params as { id: string };
    const body = request.body as { notificationId?: string } | null;

    if (!body?.notificationId) {
      throw app.httpErrors.notFound("Notification not found");
    }

    const notification = await db.notification.findFirst({
      where: {
        id: body.notificationId,
        alertId: params.id
      }
    });

    if (!notification) {
      throw app.httpErrors.notFound("Notification not found");
    }

    return db.notification.update({
      where: { id: notification.id },
      data: { acknowledged: true, acknowledgedAt: new Date() }
    });
  });

  app.get("/api/v1/dashboard/health", async () => {
    const servers = await db.server.findMany({ where: { active: true } });
    const cards: Array<{
      serverId: string;
      displayName: string;
      lastJobStatus: JobStatus | null;
      diskPercent: number | null;
      memoryPercent: number | null;
      lastRunAt: Date | null;
    }> = [];

    for (const server of servers) {
      const job = await db.job.findFirst({
        where: { serverId: server.id },
        orderBy: { enqueuedAt: "desc" }
      });

      let diskPercent: number | null = null;
      let memoryPercent: number | null = null;

      if (job) {
        const results = await db.jobResult.findMany({
          where: { jobId: job.id },
          orderBy: { stepOrder: "asc" }
        });

        for (const result of results) {
          const values = result.parsedValues as Record<string, unknown> | null;
          if (!values) continue;

          if (typeof values.disk_percent === "number") {
            diskPercent = values.disk_percent;
          }
          if (typeof values.memory_percent === "number") {
            memoryPercent = values.memory_percent;
          }
        }
      }

      cards.push({
        serverId: server.id,
        displayName: server.displayName,
        lastJobStatus: job?.status ?? null,
        diskPercent,
        memoryPercent,
        lastRunAt: job?.completedAt ?? null
      });
    }

    return cards;
  });

  app.post("/api/v1/internal/jobs/:id/evaluate-alerts", async (request) => {
    const authHeader = request.headers["x-internal-token"];
    if (authHeader !== env.INTERNAL_API_TOKEN) {
      throw app.httpErrors.unauthorized("Missing internal token");
    }

    const params = request.params as { id: string };
    const body = request.body as {
      metrics: Array<{
        serverId: string;
        metric: string;
        value: number;
      }>;
    };

    const job = await db.job.findUnique({ where: { id: params.id } });
    if (!job) {
      throw app.httpErrors.notFound("job not found");
    }

    await evaluateAlertsForMetrics(db, body.metrics);
    return { ok: true };
  });

  // ---------------------------------------------------------------------------
  // Audit log
  // ---------------------------------------------------------------------------

  const auditQuerySchema = z.object({
    actor: z.string().optional(),
    action: z.string().optional(),
    resource: z.string().optional(),
    from: z.string().datetime({ offset: true }).optional(),
    to: z.string().datetime({ offset: true }).optional(),
    limit: z.coerce.number().int().min(1).max(500).optional(),
    offset: z.coerce.number().int().min(0).optional()
  });

  app.get("/api/v1/audit", async (request) => {
    const parsed = auditQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      throw app.httpErrors.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const q = parsed.data;
    return queryAuditEvents(db, {
      actor: q.actor,
      action: q.action,
      resource: q.resource,
      from: q.from ? new Date(q.from) : undefined,
      to: q.to ? new Date(q.to) : undefined,
      limit: q.limit,
      offset: q.offset
    });
  });

  app.setErrorHandler((error, request, reply) => {
    request.log.error(error);
    if (error && typeof error === "object" && "statusCode" in error) {
      const statusCode = (error as { statusCode: number }).statusCode;
      const message =
        "message" in error && typeof error.message === "string"
          ? error.message
          : "Request failed";
      return reply.code(statusCode).send({ error: message });
    }

    return reply.code(500).send({ error: "Internal server error" });
  });

  return app;
}

declare module "fastify" {
  interface FastifyRequest {
    user?: {
      id: string;
      role: "admin" | "operator";
      sessionId: string;
    };
  }
}
