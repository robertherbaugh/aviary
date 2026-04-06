"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../components/api";
import { formatCompactDate, formatDateTime } from "../../components/format";
import { Shell } from "../../components/shell";

type RotationStatus = "success" | "in_progress" | "failed";

type RotationRecord = {
  id: string;
  status: RotationStatus;
  triggeredBy: "manual" | "scheduled";
  startedAt: string;
  completedAt: string | null;
  error: string | null;
};

type CredentialRotation = {
  id: string;
  name: string;
  type: string;
  username: string;
  rotationEnabled: boolean;
  rotationSchedule: string | null;
  lastRotatedAt: string | null;
  lastRotationStatus: RotationStatus | null;
  history: RotationRecord[];
};

type ScheduleFormState = {
  credentialId: string;
  enabled: boolean;
  schedule: string;
};

function statusBadge(status: RotationStatus | null): string {
  if (status === "success") return "badge badge-green";
  if (status === "in_progress") return "badge badge-yellow";
  if (status === "failed") return "badge badge-red";
  return "badge badge-yellow";
}

function statusLabel(status: RotationStatus | null): string {
  if (!status) return "never rotated";
  if (status === "in_progress") return "in progress";
  return status;
}

export default function CredentialRotationPage() {
  const [rows, setRows] = useState<CredentialRotation[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState<string | null>(null);
  const [savingSchedule, setSavingSchedule] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [scheduleForm, setScheduleForm] = useState<ScheduleFormState>({
    credentialId: "",
    enabled: false,
    schedule: ""
  });
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch<CredentialRotation[]>("/api/v1/credentials/rotation");
      setRows(response);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unable to load credential rotation data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
  }, []);

  async function rotateNow(id: string) {
    const row = rows.find((r) => r.id === id);
    const confirmed = window.confirm(`Rotate credential "${row?.name ?? id}" now?`);
    if (!confirmed) return;

    setRotating(id);
    setError(null);
    try {
      await apiFetch(`/api/v1/credentials/${id}/rotate`, { method: "POST" });
      await loadData();
    } catch (rotateError) {
      setError(rotateError instanceof Error ? rotateError.message : "Rotation failed");
    } finally {
      setRotating(null);
    }
  }

  function openScheduleEdit(row: CredentialRotation) {
    setEditingScheduleId(row.id);
    setScheduleForm({
      credentialId: row.id,
      enabled: row.rotationEnabled,
      schedule: row.rotationSchedule ?? ""
    });
  }

  async function saveSchedule(event: FormEvent) {
    event.preventDefault();

    if (scheduleForm.enabled && !scheduleForm.schedule.trim()) {
      setError("Cron schedule is required when rotation is enabled.");
      return;
    }

    setSavingSchedule(scheduleForm.credentialId);
    setError(null);
    try {
      await apiFetch(`/api/v1/credentials/${scheduleForm.credentialId}/rotation-schedule`, {
        method: "PATCH",
        body: {
          enabled: scheduleForm.enabled,
          schedule: scheduleForm.enabled ? scheduleForm.schedule.trim() : null
        }
      });
      setEditingScheduleId(null);
      await loadData();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Unable to save rotation schedule");
    } finally {
      setSavingSchedule(null);
    }
  }

  const enabledCount = rows.filter((r) => r.rotationEnabled).length;
  const failedCount = rows.filter((r) => r.lastRotationStatus === "failed").length;

  return (
    <Shell
      title="Credential Rotation"
      subtitle="Rotate credentials manually or on a schedule, and track rotation history."
      actions={
        <>
          <a className="btn btn-secondary" href="/credentials">
            Manage Credentials
          </a>
          <button className="btn btn-secondary" type="button" onClick={() => void loadData()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </>
      }
    >
      {error ? <p className="error">{error}</p> : null}

      <section className="stat-grid">
        <article className="panel stat-card">
          <p className="stat-label">Total Credentials</p>
          <p className="stat-value">{rows.length}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Auto-Rotation Enabled</p>
          <p className="stat-value">{enabledCount}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Manual Only</p>
          <p className="stat-value">{rows.length - enabledCount}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Last Rotation Failed</p>
          <p className="stat-value">{failedCount}</p>
        </article>
      </section>

      <article className="panel table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Credential</th>
              <th>Type</th>
              <th>Last Rotation</th>
              <th>Schedule</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5}>
                  <div className="empty">{loading ? "Loading..." : "No credentials found."}</div>
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <>
                  <tr key={row.id}>
                    <td>
                      <p className="m-0 font-semibold">{row.name}</p>
                      <p className="m-0 text-xs text-slate-500">{row.username}</p>
                    </td>
                    <td>
                      <span className={row.type === "ssh_key" ? "badge badge-green" : "badge badge-yellow"}>
                        {row.type === "ssh_key" ? "ssh_key" : "password"}
                      </span>
                    </td>
                    <td>
                      {row.lastRotatedAt ? (
                        <div>
                          <span className={statusBadge(row.lastRotationStatus)}>
                            {statusLabel(row.lastRotationStatus)}
                          </span>
                          <p className="m-0 mt-1 text-xs text-muted">{formatCompactDate(row.lastRotatedAt)}</p>
                        </div>
                      ) : (
                        <span className="text-muted text-sm">never rotated</span>
                      )}
                    </td>
                    <td>
                      {row.rotationEnabled ? (
                        <div>
                          <span className="badge badge-green">auto</span>
                          <p className="m-0 mt-1 font-mono text-xs">{row.rotationSchedule}</p>
                        </div>
                      ) : (
                        <span className="badge badge-yellow">manual only</span>
                      )}
                    </td>
                    <td>
                      <div className="actions">
                        <button
                          className="btn btn-secondary"
                          type="button"
                          onClick={() => setExpandedId(expandedId === row.id ? null : row.id)}
                        >
                          {expandedId === row.id ? "Hide History" : "History"}
                        </button>
                        <button
                          className="btn btn-secondary"
                          type="button"
                          onClick={() => openScheduleEdit(row)}
                        >
                          Schedule
                        </button>
                        <button
                          className="btn btn-primary"
                          type="button"
                          onClick={() => void rotateNow(row.id)}
                          disabled={rotating === row.id || row.lastRotationStatus === "in_progress"}
                        >
                          {rotating === row.id ? "Rotating..." : "Rotate Now"}
                        </button>
                      </div>
                    </td>
                  </tr>

                  {editingScheduleId === row.id ? (
                    <tr key={`${row.id}-schedule`}>
                      <td colSpan={5} className="p-0">
                        <div className="p-4 bg-slate-50 dark:bg-slate-800">
                          <p className="section-label mb-2">Configure Rotation Schedule</p>
                          <form className="space-y-3" onSubmit={(event) => void saveSchedule(event)}>
                            <div className="form-grid">
                              <div className="field-wrap col-span-12">
                                <label className="flex items-center gap-2 cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={scheduleForm.enabled}
                                    onChange={(event) =>
                                      setScheduleForm((current) => ({
                                        ...current,
                                        enabled: event.target.checked
                                      }))
                                    }
                                  />
                                  <span>Enable automatic rotation</span>
                                </label>
                              </div>

                              {scheduleForm.enabled ? (
                                <div className="field-wrap col-span-12 md:col-span-8">
                                  <label htmlFor={`schedule-cron-${row.id}`}>Cron Schedule</label>
                                  <input
                                    className="field font-mono"
                                    id={`schedule-cron-${row.id}`}
                                    value={scheduleForm.schedule}
                                    onChange={(event) =>
                                      setScheduleForm((current) => ({
                                        ...current,
                                        schedule: event.target.value
                                      }))
                                    }
                                    placeholder="0 0 * * 0  (every Sunday at midnight)"
                                  />
                                  <p className="m-0 text-xs text-slate-500">
                                    Standard cron syntax, e.g. <code>0 0 1 * *</code> for the 1st of every month.
                                  </p>
                                </div>
                              ) : null}
                            </div>

                            <div className="actions">
                              <button
                                className="btn btn-primary"
                                type="submit"
                                disabled={savingSchedule === row.id}
                              >
                                {savingSchedule === row.id ? "Saving..." : "Save Schedule"}
                              </button>
                              <button
                                className="btn btn-secondary"
                                type="button"
                                onClick={() => setEditingScheduleId(null)}
                                disabled={savingSchedule === row.id}
                              >
                                Cancel
                              </button>
                            </div>
                          </form>
                        </div>
                      </td>
                    </tr>
                  ) : null}

                  {expandedId === row.id ? (
                    <tr key={`${row.id}-history`}>
                      <td colSpan={5} className="p-0">
                        <div className="p-4 bg-slate-50 dark:bg-slate-800">
                          <p className="section-label mb-2">Rotation History</p>
                          {row.history.length === 0 ? (
                            <div className="empty">No rotation history.</div>
                          ) : (
                            <div className="space-y-2">
                              {row.history.map((record) => (
                                <div key={record.id} className="alert-notification-card">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className={statusBadge(record.status)}>{statusLabel(record.status)}</span>
                                    <span className="badge badge-green">{record.triggeredBy}</span>
                                    <p className="m-0 text-xs text-muted">{formatDateTime(record.startedAt)}</p>
                                    {record.completedAt ? (
                                      <p className="m-0 text-xs text-muted">
                                        → {formatCompactDate(record.completedAt)}
                                      </p>
                                    ) : null}
                                  </div>
                                  {record.error ? (
                                    <p className="m-0 mt-1 text-sm text-red-600">{record.error}</p>
                                  ) : null}
                                </div>
                              ))}
                            </div>
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
    </Shell>
  );
}
