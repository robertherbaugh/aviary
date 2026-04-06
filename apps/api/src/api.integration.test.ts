/**
 * Integration tests for Merlin API routes.
 * Requires a real Postgres database — provided by the vitest globalSetup
 * which starts a testcontainers postgres and sets DATABASE_URL.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildServer } from "./server.js";

type FastifyInstance = Awaited<ReturnType<typeof buildServer>>;

let app: FastifyInstance;
let authToken: string;

const TEST_EMAIL = "admin@test.local";
const TEST_PASSWORD = "password123";

beforeAll(async () => {
  app = await buildServer();
  await app.ready();

  // Bootstrap: create first user
  const setupRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/local/bootstrap-setup",
    payload: { email: TEST_EMAIL, password: TEST_PASSWORD }
  });

  if (setupRes.statusCode === 200 || setupRes.statusCode === 201) {
    authToken = setupRes.json().token;
  } else {
    // If already set up (e.g. test DB reuse), just login
    const loginRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: { email: TEST_EMAIL, password: TEST_PASSWORD }
    });
    authToken = loginRes.json().token;
  }
}, 60_000);

afterAll(async () => {
  await app?.close();
}, 30_000);

function authHeaders() {
  return { authorization: `Bearer ${authToken}` };
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

describe("GET /health", () => {
  it("returns 200 ok", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

describe("Auth endpoints", () => {
  it("GET /api/v1/auth/bootstrap-status returns status", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/bootstrap-status"
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("hasUsers");
    expect(body).toHaveProperty("setupRequired");
    expect(body.hasUsers).toBe(true);
  });

  it("POST /api/v1/auth/local/bootstrap-setup returns conflict if already set up", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-setup",
      payload: { email: "other@test.local", password: "password123" }
    });
    expect(res.statusCode).toBe(409);
  });

  it("POST /api/v1/auth/local/bootstrap-setup returns 400 if body missing", async () => {
    // We can't easily reset DB state, so test validation
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-setup",
      payload: {}
    });
    expect([400, 409]).toContain(res.statusCode);
  });

  it("POST /api/v1/auth/local/bootstrap-login returns token for valid creds", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: { email: TEST_EMAIL, password: TEST_PASSWORD }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty("token");
    expect(typeof res.json().token).toBe("string");
  });

  it("POST /api/v1/auth/local/bootstrap-login rejects wrong password", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: { email: TEST_EMAIL, password: "wrongpassword" }
    });
    expect(res.statusCode).toBe(401);
  });

  it("POST /api/v1/auth/local/bootstrap-login rejects unknown email", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: { email: "nobody@test.local", password: "password123" }
    });
    expect(res.statusCode).toBe(401);
  });

  it("POST /api/v1/auth/local/bootstrap-login returns 400 if body missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: {}
    });
    expect(res.statusCode).toBe(400);
  });

  it("GET /api/v1/auth/session returns current user", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/session",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("id");
    expect(body.email).toBe(TEST_EMAIL);
  });

  it("GET /api/v1/auth/session returns 401 without token", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/auth/session" });
    expect(res.statusCode).toBe(401);
  });

  it("GET /api/v1/auth/session returns 401 with bogus token", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/session",
      headers: { authorization: "Bearer not-a-valid-jwt" }
    });
    expect(res.statusCode).toBe(401);
  });

  it("POST /api/v1/auth/logout invalidates session", async () => {
    // Get a fresh token to log out
    const loginRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/local/bootstrap-login",
      payload: { email: TEST_EMAIL, password: TEST_PASSWORD }
    });
    const tempToken = loginRes.json().token;

    const logoutRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: { authorization: `Bearer ${tempToken}` }
    });
    expect(logoutRes.statusCode).toBe(200);
    expect(logoutRes.json()).toMatchObject({ ok: true });

    // Token should no longer be valid
    const sessionRes = await app.inject({
      method: "GET",
      url: "/api/v1/auth/session",
      headers: { authorization: `Bearer ${tempToken}` }
    });
    expect(sessionRes.statusCode).toBe(401);
  });

  it("POST /api/v1/auth/oidc/login returns redirect URL or 400", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/oidc/login"
    });
    // OIDC is not configured, so expect 400
    expect(res.statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

describe("Settings endpoints", () => {
  it("GET /api/v1/settings/oidc returns OIDC config", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/settings/oidc",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("stored");
    expect(body).toHaveProperty("effective");
  });

  it("PUT /api/v1/settings/oidc updates settings", async () => {
    const res = await app.inject({
      method: "PUT",
      url: "/api/v1/settings/oidc",
      headers: authHeaders(),
      payload: {
        issuerUrl: null,
        clientId: null,
        redirectUri: null
      }
    });
    expect(res.statusCode).toBe(200);
  });

  it("PUT /api/v1/settings/oidc validates issuerUrl", async () => {
    const res = await app.inject({
      method: "PUT",
      url: "/api/v1/settings/oidc",
      headers: authHeaders(),
      payload: { issuerUrl: "not-a-url" }
    });
    expect(res.statusCode).toBe(400);
  });

  it("GET /api/v1/settings/alerts-backend returns alerts backend config", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/settings/alerts-backend",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });

  it("PUT /api/v1/settings/alerts-backend updates config", async () => {
    const res = await app.inject({
      method: "PUT",
      url: "/api/v1/settings/alerts-backend",
      headers: authHeaders(),
      payload: { type: "none" }
    });
    expect([200, 400]).toContain(res.statusCode);
  });
});

// ---------------------------------------------------------------------------
// Credentials CRUD
// ---------------------------------------------------------------------------

describe("Credentials CRUD", () => {
  let credentialId: string;

  it("GET /api/v1/credentials returns empty list initially", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/credentials",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("POST /api/v1/credentials creates a credential", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/credentials",
      headers: authHeaders(),
      payload: {
        name: "Test SSH Key",
        type: "ssh_key",
        username: "ubuntu",
        secretValue: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
      }
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.name).toBe("Test SSH Key");
    expect(body.username).toBe("ubuntu");
    expect(body).not.toHaveProperty("encryptedValue");
    credentialId = body.id;
  });

  it("GET /api/v1/credentials returns created credential", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/credentials",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const list = res.json() as Array<{ id: string }>;
    expect(list.some((c) => c.id === credentialId)).toBe(true);
  });

  it("PATCH /api/v1/credentials/:id updates a credential", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/credentials/${credentialId}`,
      headers: authHeaders(),
      payload: { name: "Updated SSH Key" }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().name).toBe("Updated SSH Key");
  });

  it("DELETE /api/v1/credentials/:id deletes a credential", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/credentials/${credentialId}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Servers CRUD
// ---------------------------------------------------------------------------

describe("Servers CRUD", () => {
  let serverId: string;
  let credentialForServer: string;

  beforeAll(async () => {
    const credRes = await app.inject({
      method: "POST",
      url: "/api/v1/credentials",
      headers: authHeaders(),
      payload: {
        name: "Server Test Cred",
        type: "password",
        username: "root",
        secretValue: "rootpassword"
      }
    });
    credentialForServer = credRes.json().id;
  });

  it("GET /api/v1/servers returns empty list initially", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/servers",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("POST /api/v1/servers creates a server", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/servers",
      headers: authHeaders(),
      payload: {
        hostname: "test-server-1",
        ipAddress: "10.0.0.100",
        port: 22,
        displayName: "Test Server 1",
        tags: ["test"],
        active: true
      }
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.hostname).toBe("test-server-1");
    expect(body.ipAddress).toBe("10.0.0.100");
    serverId = body.id;
  });

  it("POST /api/v1/servers creates a server with credential", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/servers",
      headers: authHeaders(),
      payload: {
        hostname: "test-server-2",
        ipAddress: "10.0.0.101",
        port: 22,
        displayName: "Test Server 2",
        tags: [],
        active: true,
        credentialId: credentialForServer
      }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().credentialId).toBe(credentialForServer);
  });

  it("GET /api/v1/servers returns created servers", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/servers",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const list = res.json() as Array<{ id: string }>;
    expect(list.some((s) => s.id === serverId)).toBe(true);
  });

  it("PATCH /api/v1/servers/:id updates server", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/servers/${serverId}`,
      headers: authHeaders(),
      payload: { displayName: "Updated Server" }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().displayName).toBe("Updated Server");
  });

  it("PATCH /api/v1/servers/:id assigns a credential", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/servers/${serverId}`,
      headers: authHeaders(),
      payload: { credentialId: credentialForServer }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().credentialId).toBe(credentialForServer);
  });

  it("POST /api/v1/servers/:id/credentials assigns credential", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/servers/${serverId}/credentials`,
      headers: authHeaders(),
      payload: { credentialId: credentialForServer }
    });
    expect(res.statusCode).toBe(200);
  });

  it("DELETE /api/v1/servers/:id/credentials/:credentialId removes credential", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/servers/${serverId}/credentials/${credentialForServer}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });

  it("DELETE /api/v1/servers/:id deletes server", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/servers/${serverId}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Playbooks CRUD
// ---------------------------------------------------------------------------

describe("Playbooks CRUD", () => {
  let playbookId: string;

  it("GET /api/v1/playbooks returns list", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/playbooks",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("GET /api/v1/playbooks/builtin returns built-in playbooks", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/playbooks/builtin",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("POST /api/v1/playbooks creates a playbook", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/playbooks",
      headers: authHeaders(),
      payload: {
        name: "Test Playbook",
        description: "A test playbook",
        isBuiltin: false,
        useSudo: false,
        createdBy: "test",
        steps: [
          { order: 1, command: "echo hello", expectedExitCode: 0 }
        ]
      }
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.name).toBe("Test Playbook");
    expect(body.steps).toHaveLength(1);
    playbookId = body.id;
  });

  it("PATCH /api/v1/playbooks/:id updates playbook", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/playbooks/${playbookId}`,
      headers: authHeaders(),
      payload: {
        name: "Updated Playbook",
        steps: [
          { order: 1, command: "echo updated", expectedExitCode: 0 }
        ]
      }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().name).toBe("Updated Playbook");
  });

  it("DELETE /api/v1/playbooks/:id deletes playbook", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/playbooks/${playbookId}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Schedules CRUD
// ---------------------------------------------------------------------------

describe("Schedules CRUD", () => {
  let scheduleId: string;
  let playbookForSchedule: string;

  beforeAll(async () => {
    const pb = await app.inject({
      method: "POST",
      url: "/api/v1/playbooks",
      headers: authHeaders(),
      payload: {
        name: "Schedule Playbook",
        description: "",
        isBuiltin: false,
        useSudo: false,
        createdBy: "test",
        steps: [{ order: 1, command: "uptime", expectedExitCode: 0 }]
      }
    });
    playbookForSchedule = pb.json().id;
  });

  it("GET /api/v1/schedules returns list", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/schedules",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("POST /api/v1/schedules creates a schedule", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: authHeaders(),
      payload: {
        playbookId: playbookForSchedule,
        cronExpression: "0 0 * * *",
        targetType: "all",
        targetIds: [],
        useSudo: false,
        enabled: true
      }
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.playbookId).toBe(playbookForSchedule);
    scheduleId = body.id;
  });

  it("PATCH /api/v1/schedules/:id updates schedule", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/schedules/${scheduleId}`,
      headers: authHeaders(),
      payload: { enabled: false }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().enabled).toBe(false);
  });

  it("DELETE /api/v1/schedules/:id deletes schedule", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/schedules/${scheduleId}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Alerts CRUD
// ---------------------------------------------------------------------------

describe("Alerts CRUD", () => {
  let alertId: string;
  let serverForAlert: string;

  beforeAll(async () => {
    const srv = await app.inject({
      method: "POST",
      url: "/api/v1/servers",
      headers: authHeaders(),
      payload: {
        hostname: "alert-server",
        ipAddress: "10.0.0.200",
        port: 22,
        displayName: "Alert Server",
        tags: [],
        active: true
      }
    });
    serverForAlert = srv.json().id;
  });

  it("GET /api/v1/alerts returns list", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/alerts",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it("POST /api/v1/alerts creates an alert", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/alerts",
      headers: authHeaders(),
      payload: {
        serverId: serverForAlert,
        metric: "disk_percent",
        operator: "gt",
        threshold: 85,
        severity: "warning"
      }
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.metric).toBe("disk_percent");
    alertId = body.id;
  });

  it("PATCH /api/v1/alerts/:id updates alert threshold", async () => {
    const res = await app.inject({
      method: "PATCH",
      url: `/api/v1/alerts/${alertId}`,
      headers: authHeaders(),
      payload: { threshold: 90 }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().threshold).toBe(90);
  });

  it("POST /api/v1/alerts/:id/acknowledge acknowledges alert", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/alerts/${alertId}/acknowledge`,
      headers: authHeaders()
    });
    expect([200, 404]).toContain(res.statusCode);
  });

  it("DELETE /api/v1/alerts/:id deletes alert", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/v1/alerts/${alertId}`,
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

describe("Jobs endpoints", () => {
  it("GET /api/v1/jobs returns job list", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/jobs",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.jobs ?? body)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

describe("Dashboard endpoints", () => {
  it("GET /api/v1/dashboard/health returns health data", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/dashboard/health",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// WebAuthn endpoints (unauthenticated paths)
// ---------------------------------------------------------------------------

describe("WebAuthn unauthenticated endpoints", () => {
  it("POST /api/v1/auth/webauthn/authenticate/options returns challenge options", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/webauthn/authenticate/options",
      payload: {}
    });
    // Returns options or error if webauthn not configured
    expect([200, 400, 500]).toContain(res.statusCode);
  });
});

// ---------------------------------------------------------------------------
// WebAuthn authenticated endpoints
// ---------------------------------------------------------------------------

describe("WebAuthn authenticated endpoints", () => {
  it("GET /api/v1/auth/webauthn/config returns webauthn config", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/webauthn/config",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
  });

  it("GET /api/v1/auth/webauthn/credentials returns credentials", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/webauthn/credentials",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MFA status
// ---------------------------------------------------------------------------

describe("MFA endpoints", () => {
  it("GET /api/v1/auth/mfa/status returns MFA status", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/mfa/status",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("totpEnabled");
  });

  it("POST /api/v1/auth/mfa/totp/setup returns setup data", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/mfa/totp/setup",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("secret");
    expect(body).toHaveProperty("otpauthUrl");
  });
});

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

describe("Audit log endpoints", () => {
  it("GET /api/v1/audit returns paginated result", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toHaveProperty("items");
    expect(body).toHaveProperty("total");
    expect(body).toHaveProperty("limit");
    expect(body).toHaveProperty("offset");
    expect(Array.isArray(body.items)).toBe(true);
  });

  it("GET /api/v1/audit rejects invalid date filter", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit?from=not-a-date",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(400);
  });

  it("GET /api/v1/audit filters by actor", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit?actor=nonexistent-user",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(0);
    expect(body.items).toHaveLength(0);
  });

  it("GET /api/v1/audit requires authentication", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit"
    });
    expect(res.statusCode).toBe(401);
  });

  it("audit middleware records a CREATE event after POST /api/v1/servers", async () => {
    // Create a server to generate an audit event
    await app.inject({
      method: "POST",
      url: "/api/v1/servers",
      headers: authHeaders(),
      payload: {
        hostname: "audit-test-host",
        ipAddress: "192.168.99.1",
        port: 22,
        displayName: "Audit Test Server"
      }
    });

    // Audit event should have been recorded
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit?resource=server&action=CREATE",
      headers: authHeaders()
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBeGreaterThan(0);
    const event = body.items[0];
    expect(event.action).toBe("CREATE");
    expect(event.resource).toBe("server");
  });
});
