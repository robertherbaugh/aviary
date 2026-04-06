"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../components/api";
import { formatCompactDate, formatDateTime } from "../../components/format";
import { Shell } from "../../components/shell";

type ChannelType = "email" | "webhook" | "slack";
type DeliveryStatus = "success" | "failed" | "pending";

type DeliveryRecord = {
  id: string;
  status: DeliveryStatus;
  message: string;
  sentAt: string;
};

type NotificationChannel = {
  id: string;
  name: string;
  type: ChannelType;
  target: string;
  enabled: boolean;
  createdAt: string;
  lastDeliveryAt: string | null;
  lastDeliveryStatus: DeliveryStatus | null;
  recentDeliveries: DeliveryRecord[];
};

type ChannelFormState = {
  name: string;
  type: ChannelType;
  target: string;
  enabled: boolean;
};

const initialForm: ChannelFormState = {
  name: "",
  type: "email",
  target: "",
  enabled: true
};

function targetPlaceholder(type: ChannelType): string {
  if (type === "email") return "ops@example.com";
  if (type === "webhook") return "https://hooks.example.com/notify";
  return "https://hooks.slack.com/services/T000/B000/xxxx";
}

function targetLabel(type: ChannelType): string {
  if (type === "email") return "Email Address";
  if (type === "webhook") return "Webhook URL";
  return "Slack Webhook URL";
}

function deliveryBadge(status: DeliveryStatus | null): string {
  if (status === "success") return "badge badge-green";
  if (status === "failed") return "badge badge-red";
  return "badge badge-yellow";
}

function statusLabel(status: DeliveryStatus | null): string {
  if (!status) return "no deliveries";
  return status;
}

export default function NotificationsPage() {
  const [rows, setRows] = useState<NotificationChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [form, setForm] = useState<ChannelFormState>(initialForm);
  const [error, setError] = useState<string | null>(null);

  async function loadChannels() {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch<NotificationChannel[]>("/api/v1/notification-channels");
      setRows(response);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unable to load notification channels");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadChannels();
  }, []);

  function openCreate() {
    setEditingId(null);
    setForm(initialForm);
    setShowForm(true);
    setError(null);
  }

  function openEdit(row: NotificationChannel) {
    setEditingId(row.id);
    setForm({
      name: row.name,
      type: row.type,
      target: row.target,
      enabled: row.enabled
    });
    setShowForm(true);
    setError(null);
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();

    if (!form.name.trim()) {
      setError("Channel name is required.");
      return;
    }
    if (!form.target.trim()) {
      setError("Target is required.");
      return;
    }

    setSaving(true);
    setError(null);

    const payload = {
      name: form.name.trim(),
      type: form.type,
      target: form.target.trim(),
      enabled: form.enabled
    };

    try {
      if (editingId) {
        await apiFetch(`/api/v1/notification-channels/${editingId}`, {
          method: "PATCH",
          body: payload
        });
      } else {
        await apiFetch("/api/v1/notification-channels", { method: "POST", body: payload });
      }

      setEditingId(null);
      setShowForm(false);
      setForm(initialForm);
      await loadChannels();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Unable to save channel");
    } finally {
      setSaving(false);
    }
  }

  async function removeChannel(id: string) {
    const confirmed = window.confirm("Delete this notification channel?");
    if (!confirmed) return;

    setError(null);
    try {
      await apiFetch(`/api/v1/notification-channels/${id}`, { method: "DELETE" });
      if (editingId === id) {
        setEditingId(null);
        setShowForm(false);
        setForm(initialForm);
      }
      await loadChannels();
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "Unable to delete channel");
    }
  }

  async function testChannel(id: string) {
    setTesting(id);
    setError(null);
    try {
      await apiFetch(`/api/v1/notification-channels/${id}/test`, { method: "POST" });
      await loadChannels();
    } catch (testError) {
      setError(testError instanceof Error ? testError.message : "Test delivery failed");
    } finally {
      setTesting(null);
    }
  }

  const enabledCount = rows.filter((r) => r.enabled).length;
  const failedCount = rows.filter((r) => r.lastDeliveryStatus === "failed").length;

  return (
    <Shell
      title="Notification Channels"
      subtitle="Manage where alert notifications are delivered — email, webhook, or Slack."
      actions={
        <>
          <button className="btn btn-secondary" type="button" onClick={() => void loadChannels()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button className="btn btn-primary" type="button" onClick={openCreate}>
            New Channel
          </button>
        </>
      }
    >
      {error ? <p className="error">{error}</p> : null}

      <section className="stat-grid">
        <article className="panel stat-card">
          <p className="stat-label">Total Channels</p>
          <p className="stat-value">{rows.length}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Enabled</p>
          <p className="stat-value">{enabledCount}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Disabled</p>
          <p className="stat-value">{rows.length - enabledCount}</p>
        </article>
        <article className="panel stat-card">
          <p className="stat-label">Recent Failures</p>
          <p className="stat-value">{failedCount}</p>
        </article>
      </section>

      {showForm ? (
        <article className="panel form-panel">
          <form className="space-y-3" onSubmit={(event) => void onSubmit(event)}>
            <div className="form-grid">
              <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-4">
                <label htmlFor="channel-name">Channel Name</label>
                <input
                  className="field"
                  id="channel-name"
                  value={form.name}
                  onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                  placeholder="e.g. Ops Email"
                />
              </div>

              <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-3">
                <label htmlFor="channel-type">Type</label>
                <select
                  className="select"
                  id="channel-type"
                  value={form.type}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      type: event.target.value as ChannelType,
                      target: ""
                    }))
                  }
                >
                  <option value="email">Email</option>
                  <option value="webhook">Webhook</option>
                  <option value="slack">Slack</option>
                </select>
              </div>

              <div className="field-wrap col-span-12 md:col-span-6 lg:col-span-5">
                <label htmlFor="channel-target">{targetLabel(form.type)}</label>
                <input
                  className="field"
                  id="channel-target"
                  type={form.type === "email" ? "email" : "url"}
                  value={form.target}
                  onChange={(event) => setForm((current) => ({ ...current, target: event.target.value }))}
                  placeholder={targetPlaceholder(form.type)}
                />
              </div>

              <div className="field-wrap col-span-12">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))}
                  />
                  <span>Enabled</span>
                </label>
              </div>
            </div>

            <div className="actions">
              <button className="btn btn-primary" type="submit" disabled={saving}>
                {saving ? "Saving..." : editingId ? "Update Channel" : "Create Channel"}
              </button>
              <button
                className="btn btn-secondary"
                type="button"
                onClick={() => {
                  setEditingId(null);
                  setShowForm(false);
                  setForm(initialForm);
                }}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </article>
      ) : null}

      <article className="panel table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Target</th>
              <th>Status</th>
              <th>Last Delivery</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={6}>
                  <div className="empty">No notification channels configured.</div>
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <>
                  <tr key={row.id}>
                    <td>
                      <p className="m-0 font-semibold">{row.name}</p>
                      <p className="m-0 text-xs text-slate-500">ID {row.id.slice(0, 8)}</p>
                    </td>
                    <td>
                      <span className="badge badge-green">{row.type}</span>
                    </td>
                    <td>
                      <span className="font-mono text-xs">{row.target}</span>
                    </td>
                    <td>
                      <span className={row.enabled ? "badge badge-green" : "badge badge-yellow"}>
                        {row.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td>
                      {row.lastDeliveryAt ? (
                        <div>
                          <span className={deliveryBadge(row.lastDeliveryStatus)}>
                            {statusLabel(row.lastDeliveryStatus)}
                          </span>
                          <p className="m-0 mt-1 text-xs text-muted">{formatCompactDate(row.lastDeliveryAt)}</p>
                        </div>
                      ) : (
                        <span className="text-muted text-sm">no deliveries</span>
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
                          onClick={() => void testChannel(row.id)}
                          disabled={testing === row.id || !row.enabled}
                        >
                          {testing === row.id ? "Sending..." : "Test"}
                        </button>
                        <button className="btn btn-secondary" type="button" onClick={() => openEdit(row)}>
                          Edit
                        </button>
                        <button className="btn btn-danger" type="button" onClick={() => void removeChannel(row.id)}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expandedId === row.id ? (
                    <tr key={`${row.id}-history`}>
                      <td colSpan={6} className="p-0">
                        <div className="p-4 bg-slate-50 dark:bg-slate-800">
                          <p className="section-label mb-2">Recent Deliveries</p>
                          {row.recentDeliveries.length === 0 ? (
                            <div className="empty">No delivery history.</div>
                          ) : (
                            <div className="space-y-2">
                              {row.recentDeliveries.map((delivery) => (
                                <div key={delivery.id} className="alert-notification-card">
                                  <div className="flex items-center gap-2">
                                    <span className={deliveryBadge(delivery.status)}>{delivery.status}</span>
                                    <p className="m-0 text-xs text-muted">{formatCompactDate(delivery.sentAt)}</p>
                                  </div>
                                  <p className="m-0 mt-1 text-sm">{delivery.message}</p>
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
