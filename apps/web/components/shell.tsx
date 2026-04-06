"use client";

import { FormEvent, ReactNode, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";
import { Nav } from "./nav";
import { clearStoredToken, getAuthToken } from "./auth";
import { apiBase } from "./api";
import webPackage from "../package.json";

type Theme = "light" | "dark";

const themeStorageKey = "aviary-theme";
const appVersion = webPackage.version ?? "0.0.0";
const searchTargets: Array<{ href: Route; terms: string[] }> = [
  { href: "/dashboard", terms: ["dashboard", "overview", "home"] },
  { href: "/servers", terms: ["servers", "server", "hosts"] },
  { href: "/credentials", terms: ["credentials", "credential", "keys", "ssh keys"] },
  { href: "/wizard", terms: ["wizard", "setup wizard", "automation wizard"] },
  { href: "/playbooks", terms: ["playbooks", "playbook", "runs"] },
  { href: "/schedules", terms: ["schedules", "schedule", "cron"] },
  { href: "/jobs", terms: ["jobs", "job", "executions"] },
  { href: "/alerts", terms: ["alerts", "alert", "notifications"] },
  {
    href: "/automation/settings/security",
    terms: ["security", "auth", "authentication", "passkeys", "webauthn", "oidc", "sso"]
  },
  {
    href: "/automation/settings/alerts-backend",
    terms: ["alerts backend", "alert backend", "webhook", "notification backend"]
  },
  {
    href: "/notifications",
    terms: ["notifications", "notification channels", "notification channel", "channels", "slack", "email channel"]
  },
  {
    href: "/audit-log",
    terms: ["audit", "audit log", "history", "activity log", "events"]
  },
  {
    href: "/credential-rotation",
    terms: ["rotation", "credential rotation", "rotate", "rotate credentials"]
  }
];

function resolveSearchTarget(rawQuery: string): Route | null {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return null;

  if (query.startsWith("/")) {
    const routeMatch = searchTargets.find((target) => target.href === query);
    return routeMatch?.href ?? null;
  }

  const exactMatch = searchTargets.find((target) => target.terms.includes(query));
  if (exactMatch) return exactMatch.href;

  const partialMatch = searchTargets.find((target) =>
    target.terms.some((term) => term.includes(query) || query.includes(term))
  );
  return partialMatch?.href ?? null;
}

function resolveThemePreference(storedTheme: string | null): Theme | null {
  if (storedTheme === "light" || storedTheme === "dark") return storedTheme;
  return null;
}

function SunIcon() {
  return (
    <svg className="theme-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9">
      <circle cx="12" cy="12" r="4.25" />
      <path d="M12 2.5v2.3M12 19.2v2.3M4.8 4.8l1.6 1.6M17.6 17.6l1.6 1.6M2.5 12h2.3M19.2 12h2.3M4.8 19.2l1.6-1.6M17.6 6.4l1.6-1.6" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg className="theme-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9">
      <path d="M14.7 3.2a8.8 8.8 0 1 0 6.1 13.3A9.4 9.4 0 0 1 14.7 3.2z" />
    </svg>
  );
}

function AppFrame({
  headerTools,
  searchValue,
  onSearchChange,
  onSearchSubmit,
  children
}: {
  headerTools?: ReactNode;
  searchValue: string;
  onSearchChange: (value: string) => void;
  onSearchSubmit: (event: FormEvent<HTMLFormElement>) => void;
  children: ReactNode;
}) {
  const currentYear = new Date().getFullYear();

  return (
    <div className="app-frame">
      <header className="app-header">
        <div className="app-header-inner">
          <div className="brand app-header-branding">
            <div className="brand-mark" aria-hidden>
              <svg
                className="brand-mark-icon"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.1"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M16 7h.01" />
                <path d="M3.4 18H12a8 8 0 0 0 8-8V7a4 4 0 0 0-7.28-2.3L2 20" />
                <path d="m20 7 2 .5-2 .5" />
                <path d="M10 18v3" />
                <path d="M14 17.75V21" />
                <path d="M7 18a6 6 0 0 0 3.84-10.61" />
              </svg>
            </div>
            <div>
              <p className="brand-title">Aviary</p>
              <p className="brand-subtitle">Server Management & Job Orchestration</p>
            </div>
          </div>

          <form className="search-pill app-header-search" onSubmit={onSearchSubmit}>
            <span className="search-icon" aria-hidden>
              ⌕
            </span>
            <input
              className="search-field"
              type="search"
              placeholder="Search sections (servers, jobs, playbooks...)"
              value={searchValue}
              onChange={(event) => onSearchChange(event.target.value)}
              aria-label="Search and jump to a section"
            />
          </form>

          <div className="app-header-user">
            {headerTools}
          </div>
        </div>
      </header>

      <div className="app-content">{children}</div>

      <footer className="app-footer">
        <div className="app-footer-inner">
          <p>Aviary Platform</p>
          <p>v{appVersion}</p>
        </div>
      </footer>
    </div>
  );
}

export function Shell({
  title,
  subtitle,
  actions,
  children
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [searchValue, setSearchValue] = useState("");
  const [theme, setTheme] = useState<Theme>("light");

  async function signOut() {
    const token = getAuthToken();
    if (token) {
      await fetch(`${apiBase()}/api/v1/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => null);
    }
    clearStoredToken();
    router.push("/sign-in");
  }

  function applyTheme(nextTheme: Theme) {
    setTheme(nextTheme);
    document.documentElement.dataset.theme = nextTheme;
    window.localStorage.setItem(themeStorageKey, nextTheme);
  }

  function toggleTheme() {
    applyTheme(theme === "dark" ? "light" : "dark");
  }

  function onSearchSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = resolveSearchTarget(searchValue);
    if (!target) return;
    setSearchValue("");
    router.push(target);
  }

  useEffect(() => {
    const token = getAuthToken();
    if (!token) {
      router.replace("/sign-in");
      return;
    }
    setReady(true);
  }, [router]);

  useEffect(() => {
    const stored = resolveThemePreference(window.localStorage.getItem(themeStorageKey));
    const preferred: Theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    const initialTheme = stored ?? preferred;
    setTheme(initialTheme);
    document.documentElement.dataset.theme = initialTheme;
  }, []);

  if (!ready) {
    return (
      <AppFrame searchValue={searchValue} onSearchChange={setSearchValue} onSearchSubmit={onSearchSubmit}>
        <div className="app-background">
          <div className="panel p-6 text-sm text-slate-600">Checking session...</div>
        </div>
      </AppFrame>
    );
  }

  return (
    <AppFrame
      headerTools={
        <>
          <button
            className="btn btn-secondary theme-toggle-btn"
            type="button"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            title={theme === "dark" ? "Light mode" : "Dark mode"}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
          </button>
          <button className="btn btn-secondary" type="button" onClick={() => void signOut()}>
            Sign Out
          </button>
        </>
      }
      searchValue={searchValue}
      onSearchChange={setSearchValue}
      onSearchSubmit={onSearchSubmit}
    >
      <div className="app-background">
        <div className="app-shell">
          <aside className="app-sidebar panel">
            <Nav />
          </aside>

          <div className="app-main">
            <main className="space-y-6">
              <div className="page-header">
                <div>
                  <h1>{title}</h1>
                  {subtitle ? <p>{subtitle}</p> : null}
                </div>
                {actions ? <div className="header-actions">{actions}</div> : null}
              </div>

              {children}
            </main>
          </div>
        </div>
      </div>
    </AppFrame>
  );
}
