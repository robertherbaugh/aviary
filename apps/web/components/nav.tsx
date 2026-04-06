"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Route } from "next";

const groups: Array<{ title: string; links: Array<{ href: Route; label: string }> }> = [
  {
    title: "Overview",
    links: [
      { href: "/dashboard", label: "Dashboard" },
      { href: "/wizard", label: "Wizard" }
    ]
  },
  {
    title: "Inventory",
    links: [
      { href: "/servers", label: "Servers" },
      { href: "/credentials", label: "Credentials" },
      { href: "/credential-rotation", label: "Credential Rotation" }
    ]
  },
  {
    title: "Automation",
    links: [
      { href: "/playbooks", label: "Playbooks" },
      { href: "/schedules", label: "Schedules" },
      { href: "/jobs", label: "Jobs" },
      { href: "/alerts", label: "Alerts" },
      { href: "/notifications", label: "Notifications" }
    ]
  },
  {
    title: "Platform",
    links: [
      { href: "/audit-log", label: "Audit Log" },
      { href: "/automation/settings/security", label: "Security" },
      { href: "/automation/settings/alerts-backend", label: "Alerts Backend" }
    ]
  }
] as const;

export function Nav() {
  const pathname = usePathname();

  return (
    <nav className="space-y-6">
      {groups.map((group) => (
        <div key={group.title} className="space-y-2">
          <p className="nav-group-title">{group.title}</p>
          <ul className="space-y-1">
            {group.links.map((link) => {
              const isActive = pathname === link.href || pathname.startsWith(`${link.href}/`);
              return (
                <li key={link.href}>
                  <Link className={`nav-link ${isActive ? "nav-link-active" : ""}`} href={link.href}>
                    {link.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
