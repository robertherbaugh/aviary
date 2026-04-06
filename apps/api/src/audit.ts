import type { PrismaClient } from "@aviary/db";

export type AuditAction = "CREATE" | "UPDATE" | "DELETE";

export type WriteAuditEventInput = {
  actor: string;
  action: AuditAction;
  resource: string;
  resourceId?: string | null;
  beforeState?: unknown;
  afterState?: unknown;
  ip?: string | null;
};

export async function writeAuditEvent(db: PrismaClient, input: WriteAuditEventInput): Promise<void> {
  await db.auditEvent.create({
    data: {
      actor: input.actor,
      action: input.action,
      resource: input.resource,
      resourceId: input.resourceId ?? null,
      beforeState: input.beforeState !== undefined ? (input.beforeState as object) : undefined,
      afterState: input.afterState !== undefined ? (input.afterState as object) : undefined,
      ip: input.ip ?? null
    }
  });
}

const METHOD_TO_ACTION: Record<string, AuditAction> = {
  POST: "CREATE",
  PUT: "UPDATE",
  PATCH: "UPDATE",
  DELETE: "DELETE"
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Extracts audit action and resource info from an HTTP method + URL path.
 * e.g. PATCH /api/v1/servers/abc-123  -> { action: "UPDATE", resource: "server", resourceId: "abc-123" }
 *      POST  /api/v1/playbooks         -> { action: "CREATE", resource: "playbook", resourceId: null }
 */
export function extractAuditInfo(
  method: string,
  url: string
): { action: AuditAction; resource: string; resourceId: string | null } | null {
  const action = METHOD_TO_ACTION[method.toUpperCase()];
  if (!action) return null;

  // Strip query string
  const path = url.split("?")[0] ?? url;

  const prefix = "/api/v1/";
  if (!path.startsWith(prefix)) return null;

  const rest = path.slice(prefix.length);
  const segments = rest.split("/").filter(Boolean);
  if (segments.length === 0) return null;

  const resourcePlural = segments[0]!;
  // Simple singularisation: strip trailing 's' from plural resource names
  const resource = singularise(resourcePlural);

  // Second segment is the resourceId when it looks like a UUID or non-action string
  const secondSegment = segments[1];
  const resourceId =
    secondSegment && UUID_RE.test(secondSegment) ? secondSegment : (secondSegment ?? null);

  return { action, resource, resourceId: resourceId ?? null };
}

function singularise(word: string): string {
  if (word.endsWith("ies")) return word.slice(0, -3) + "y"; // credentials -> credential (no, but playbooks etc.)
  if (word.endsWith("s")) return word.slice(0, -1);
  return word;
}

export type AuditQueryFilters = {
  actor?: string;
  action?: string;
  resource?: string;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
};

export async function queryAuditEvents(db: PrismaClient, filters: AuditQueryFilters) {
  const where: {
    actor?: string;
    action?: string;
    resource?: string;
    timestamp?: { gte?: Date; lte?: Date };
  } = {};

  if (filters.actor) where.actor = filters.actor;
  if (filters.action) where.action = filters.action;
  if (filters.resource) where.resource = filters.resource;

  if (filters.from || filters.to) {
    where.timestamp = {};
    if (filters.from) where.timestamp.gte = filters.from;
    if (filters.to) where.timestamp.lte = filters.to;
  }

  const limit = Math.min(filters.limit ?? 100, 500);
  const offset = filters.offset ?? 0;

  const [items, total] = await Promise.all([
    db.auditEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      take: limit,
      skip: offset
    }),
    db.auditEvent.count({ where })
  ]);

  return { items, total, limit, offset };
}
