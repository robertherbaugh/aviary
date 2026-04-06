"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../components/api";
import { formatDateTime } from "../../components/format";
import { Shell } from "../../components/shell";

type AuditEntry = {
  id: string;
  actor: string;
  action: string;
  resource: string;
  resourceId: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  createdAt: string;
};

type AuditPage = {
  entries: AuditEntry[];
  total: number;
  page: number;
  pageSize: number;
};

type FilterState = {
  actor: string;
  action: string;
  resource: string;
  from: string;
  to: string;
};

const initialFilters: FilterState = {
  actor: "",
  action: "",
  resource: "",
  from: "",
  to: ""
};

const PAGE_SIZE = 25;

function diffKeys(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...keys].filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]));
}

export default function AuditLogPage() {
  const [data, setData] = useState<AuditPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<FilterState>(initialFilters);
  const [pendingFilters, setPendingFilters] = useState<FilterState>(initialFilters);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadEntries(nextPage: number, activeFilters: FilterState) {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("page", String(nextPage));
      params.set("pageSize", String(PAGE_SIZE));
      if (activeFilters.actor.trim()) params.set("actor", activeFilters.actor.trim());
      if (activeFilters.action.trim()) params.set("action", activeFilters.action.trim());
      if (activeFilters.resource.trim()) params.set("resource", activeFilters.resource.trim());
      if (activeFilters.from.trim()) params.set("from", activeFilters.from.trim());
      if (activeFilters.to.trim()) params.set("to", activeFilters.to.trim());

      const response = await apiFetch<AuditPage>(`/api/v1/audit?${params.toString()}`);
      setData(response);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unable to load audit log");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadEntries(page, filters);
  }, []);

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    const next = { ...pendingFilters };
    setFilters(next);
    setPage(1);
    void loadEntries(1, next);
  }

  function clearFilters() {
    setPendingFilters(initialFilters);
    setFilters(initialFilters);
    setPage(1);
    void loadEntries(1, initialFilters);
  }

  function goToPage(nextPage: number) {
    setPage(nextPage);
    void loadEntries(nextPage, filters);
  }

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <Shell
      title="Audit Log"
      subtitle="Browse a filterable history of all platform actions."
      actions={
        <button className="btn btn-secondary" type="button" onClick={() => void loadEntries(page, filters)} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      }
    >
      {error ? <p className="error">{error}</p> : null}

      <article className="panel form-panel">
        <form className="space-y-3" onSubmit={applyFilters}>
          <div className="form-grid">
            <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
              <label htmlFor="audit-actor">Actor</label>
              <input
                className="field"
                id="audit-actor"
                placeholder="username or system"
                value={pendingFilters.actor}
                onChange={(event) => setPendingFilters((current) => ({ ...current, actor: event.target.value }))}
              />
            </div>

            <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
              <label htmlFor="audit-action">Action</label>
              <input
                className="field"
                id="audit-action"
                placeholder="e.g. create, update, delete"
                value={pendingFilters.action}
                onChange={(event) => setPendingFilters((current) => ({ ...current, action: event.target.value }))}
              />
            </div>

            <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
              <label htmlFor="audit-resource">Resource</label>
              <input
                className="field"
                id="audit-resource"
                placeholder="e.g. server, credential"
                value={pendingFilters.resource}
                onChange={(event) => setPendingFilters((current) => ({ ...current, resource: event.target.value }))}
              />
            </div>

            <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
              <label htmlFor="audit-from">From</label>
              <input
                className="field"
                id="audit-from"
                type="datetime-local"
                value={pendingFilters.from}
                onChange={(event) => setPendingFilters((current) => ({ ...current, from: event.target.value }))}
              />
            </div>

            <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
              <label htmlFor="audit-to">To</label>
              <input
                className="field"
                id="audit-to"
                type="datetime-local"
                value={pendingFilters.to}
                onChange={(event) => setPendingFilters((current) => ({ ...current, to: event.target.value }))}
              />
            </div>
          </div>

          <div className="actions">
            <button className="btn btn-primary" type="submit" disabled={loading}>
              Apply Filters
            </button>
            <button className="btn btn-secondary" type="button" onClick={clearFilters} disabled={loading}>
              Clear
            </button>
          </div>
        </form>
      </article>

      {data ? (
        <p className="text-sm text-muted">
          {data.total} {data.total === 1 ? "entry" : "entries"} total
          {page > 1 || totalPages > 1 ? ` — page ${page} of ${totalPages}` : ""}
        </p>
      ) : null}

      <article className="panel table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {!data || data.entries.length === 0 ? (
              <tr>
                <td colSpan={5}>
                  <div className="empty">{loading ? "Loading..." : "No audit entries found."}</div>
                </td>
              </tr>
            ) : (
              data.entries.map((entry) => (
                <>
                  <tr key={entry.id}>
                    <td className="text-sm text-muted whitespace-nowrap">{formatDateTime(entry.createdAt)}</td>
                    <td>
                      <span className="font-medium">{entry.actor}</span>
                    </td>
                    <td>
                      <span className="badge badge-green">{entry.action}</span>
                    </td>
                    <td>
                      <p className="m-0 font-medium">{entry.resource}</p>
                      {entry.resourceId ? (
                        <p className="m-0 text-xs text-slate-500">ID {entry.resourceId.slice(0, 8)}</p>
                      ) : null}
                    </td>
                    <td>
                      {entry.before ?? entry.after ? (
                        <button
                          className="btn btn-secondary"
                          type="button"
                          onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                        >
                          {expandedId === entry.id ? "Hide diff" : "Show diff"}
                        </button>
                      ) : (
                        <span className="text-muted text-sm">—</span>
                      )}
                    </td>
                  </tr>
                  {expandedId === entry.id && (entry.before ?? entry.after) ? (
                    <tr key={`${entry.id}-diff`}>
                      <td colSpan={5} className="p-0">
                        <div className="p-4 bg-slate-50 dark:bg-slate-800">
                          <p className="section-label mb-2">State Diff</p>
                          {entry.before && entry.after ? (
                            <div className="space-y-1">
                              {diffKeys(entry.before, entry.after).map((key) => (
                                <div key={key} className="font-mono text-xs grid grid-cols-[auto_1fr_1fr] gap-2 items-start">
                                  <span className="font-semibold text-slate-600">{key}</span>
                                  <span className="text-red-600 line-through">
                                    {JSON.stringify(entry.before![key])}
                                  </span>
                                  <span className="text-green-700">
                                    {JSON.stringify(entry.after![key])}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : entry.after ? (
                            <pre className="text-xs overflow-auto">{JSON.stringify(entry.after, null, 2)}</pre>
                          ) : (
                            <pre className="text-xs overflow-auto">{JSON.stringify(entry.before, null, 2)}</pre>
                          )}
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </>
              ))
            )}
          </tbody>
        </table>
      </article>

      {totalPages > 1 ? (
        <div className="actions justify-center">
          <button
            className="btn btn-secondary"
            type="button"
            onClick={() => goToPage(page - 1)}
            disabled={page <= 1 || loading}
          >
            Previous
          </button>
          <span className="text-sm text-muted">
            {page} / {totalPages}
          </span>
          <button
            className="btn btn-secondary"
            type="button"
            onClick={() => goToPage(page + 1)}
            disabled={page >= totalPages || loading}
          >
            Next
          </button>
        </div>
      ) : null}
    </Shell>
  );
}
