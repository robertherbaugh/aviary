import { Registry, collectDefaultMetrics, Counter, Histogram, Gauge } from "prom-client";

export const registry = new Registry();

collectDefaultMetrics({ register: registry });

export const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [registry]
});

export const httpRequestsTotal = new Counter({
  name: "http_requests_total",
  help: "Total number of HTTP requests",
  labelNames: ["method", "route", "status_code"],
  registers: [registry]
});

export const jobQueueDepth = new Gauge({
  name: "job_queue_depth",
  help: "Current number of jobs in each queue by state",
  labelNames: ["queue", "state"],
  registers: [registry]
});
