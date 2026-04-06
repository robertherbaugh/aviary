import { describe, expect, it, vi, type Mock } from "vitest";
import { extractAuditInfo, queryAuditEvents, writeAuditEvent } from "./audit.js";
import type { PrismaClient } from "@aviary/db";

// ---------------------------------------------------------------------------
// extractAuditInfo
// ---------------------------------------------------------------------------

describe("extractAuditInfo", () => {
  it("maps POST to CREATE with resource and no resourceId", () => {
    const result = extractAuditInfo("POST", "/api/v1/servers");
    expect(result).toEqual({ action: "CREATE", resource: "server", resourceId: null });
  });

  it("maps PATCH to UPDATE with resource and resourceId (UUID)", () => {
    const id = "550e8400-e29b-41d4-a716-446655440000";
    const result = extractAuditInfo("PATCH", `/api/v1/servers/${id}`);
    expect(result).toEqual({ action: "UPDATE", resource: "server", resourceId: id });
  });

  it("maps PUT to UPDATE", () => {
    const id = "550e8400-e29b-41d4-a716-446655440001";
    const result = extractAuditInfo("PUT", `/api/v1/credentials/${id}`);
    expect(result).toEqual({ action: "UPDATE", resource: "credential", resourceId: id });
  });

  it("maps DELETE to DELETE", () => {
    const id = "550e8400-e29b-41d4-a716-446655440002";
    const result = extractAuditInfo("DELETE", `/api/v1/playbooks/${id}`);
    expect(result).toEqual({ action: "DELETE", resource: "playbook", resourceId: id });
  });

  it("returns null for GET method", () => {
    expect(extractAuditInfo("GET", "/api/v1/servers")).toBeNull();
  });

  it("returns null for non-api routes", () => {
    expect(extractAuditInfo("POST", "/health")).toBeNull();
  });

  it("strips query string before parsing", () => {
    const result = extractAuditInfo("POST", "/api/v1/schedules?foo=bar");
    expect(result).toEqual({ action: "CREATE", resource: "schedule", resourceId: null });
  });

  it("singularises 'ies' suffix (e.g. categories -> category)", () => {
    // generic singularisation test
    const result = extractAuditInfo("POST", "/api/v1/entries");
    expect(result?.resource).toBe("entry");
  });

  it("handles sub-action paths (non-UUID second segment)", () => {
    const result = extractAuditInfo("POST", "/api/v1/alerts/abc123/acknowledge");
    expect(result).toMatchObject({ action: "CREATE", resource: "alert" });
  });
});

// ---------------------------------------------------------------------------
// writeAuditEvent
// ---------------------------------------------------------------------------

describe("writeAuditEvent", () => {
  function makeMockDb() {
    return {
      auditEvent: {
        create: vi.fn().mockResolvedValue(undefined)
      }
    } as unknown as PrismaClient;
  }

  it("calls db.auditEvent.create with all provided fields", async () => {
    const db = makeMockDb();
    await writeAuditEvent(db, {
      actor: "user-1",
      action: "CREATE",
      resource: "server",
      resourceId: "srv-123",
      ip: "10.0.0.1"
    });

    expect((db.auditEvent.create as Mock)).toHaveBeenCalledOnce();
    const call = (db.auditEvent.create as Mock).mock.calls[0] as [{ data: Record<string, unknown> }];
    const data = call[0].data;
    expect(data.actor).toBe("user-1");
    expect(data.action).toBe("CREATE");
    expect(data.resource).toBe("server");
    expect(data.resourceId).toBe("srv-123");
    expect(data.ip).toBe("10.0.0.1");
  });

  it("sets resourceId to null when omitted", async () => {
    const db = makeMockDb();
    await writeAuditEvent(db, { actor: "system", action: "DELETE", resource: "credential" });

    const call = (db.auditEvent.create as Mock).mock.calls[0] as [{ data: Record<string, unknown> }];
    const data = call[0].data;
    expect(data.resourceId).toBeNull();
    expect(data.ip).toBeNull();
  });

  it("passes beforeState and afterState as-is", async () => {
    const db = makeMockDb();
    const before = { name: "old" };
    const after = { name: "new" };
    await writeAuditEvent(db, {
      actor: "user-1",
      action: "UPDATE",
      resource: "playbook",
      beforeState: before,
      afterState: after
    });

    const call = (db.auditEvent.create as Mock).mock.calls[0] as [{ data: Record<string, unknown> }];
    const data = call[0].data;
    expect(data.beforeState).toEqual(before);
    expect(data.afterState).toEqual(after);
  });
});

// ---------------------------------------------------------------------------
// queryAuditEvents
// ---------------------------------------------------------------------------

describe("queryAuditEvents", () => {
  function makeMockDb(items: unknown[] = [], total = 0) {
    return {
      auditEvent: {
        findMany: vi.fn().mockResolvedValue(items),
        count: vi.fn().mockResolvedValue(total)
      }
    } as unknown as PrismaClient;
  }

  it("returns items, total, limit, and offset", async () => {
    const mockItems = [{ id: "1", actor: "user-1", action: "CREATE", resource: "server" }];
    const db = makeMockDb(mockItems, 1);

    const result = await queryAuditEvents(db, {});
    expect(result.items).toEqual(mockItems);
    expect(result.total).toBe(1);
    expect(result.limit).toBe(100); // default
    expect(result.offset).toBe(0);  // default
  });

  it("applies actor filter to where clause", async () => {
    const db = makeMockDb();
    await queryAuditEvents(db, { actor: "user-xyz" });

    type FindManyArg = { where: Record<string, unknown>; take: number; skip: number };
    const call = (db.auditEvent.findMany as Mock).mock.calls[0] as [FindManyArg];
    expect(call[0].where.actor).toBe("user-xyz");
  });

  it("applies date range filter", async () => {
    const db = makeMockDb();
    const from = new Date("2026-01-01");
    const to = new Date("2026-02-01");
    await queryAuditEvents(db, { from, to });

    type FindManyArg = { where: { timestamp?: { gte?: Date; lte?: Date } } };
    const call = (db.auditEvent.findMany as Mock).mock.calls[0] as [FindManyArg];
    expect(call[0].where.timestamp?.gte).toEqual(from);
    expect(call[0].where.timestamp?.lte).toEqual(to);
  });

  it("caps limit at 500", async () => {
    const db = makeMockDb();
    await queryAuditEvents(db, { limit: 9999 });

    type FindManyArg = { take: number };
    const call = (db.auditEvent.findMany as Mock).mock.calls[0] as [FindManyArg];
    expect(call[0].take).toBe(500);
  });

  it("passes offset to skip", async () => {
    const db = makeMockDb();
    await queryAuditEvents(db, { offset: 50 });

    type FindManyArg = { skip: number };
    const call = (db.auditEvent.findMany as Mock).mock.calls[0] as [FindManyArg];
    expect(call[0].skip).toBe(50);
  });
});
