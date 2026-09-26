"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Hexagon, LayoutDashboard, Settings, ExternalLink } from "lucide-react";

export function Navbar() {
  const pathname = usePathname();
  const isDashboard = pathname === "/dashboard" || pathname === "/";
  const isSettings  = pathname === "/settings";

  return (
    <nav className="navbar">
      {/* Logo */}
      <Link href="/dashboard" className="navbar-logo">
        <div className="logo-icon">
          <Hexagon size={16} strokeWidth={1.5} color="#fff" />
        </div>
        APK Stack Analyzer
      </Link>

      {/* Nav links */}
      <div className="navbar-nav">
        <Link href="/dashboard" className={`nav-link ${isDashboard ? "active" : ""}`}>
          <LayoutDashboard size={14} />
          Dashboard
        </Link>
        <Link href="/settings" className={`nav-link ${isSettings ? "active" : ""}`}>
          <Settings size={14} />
          Settings
        </Link>
      </div>

      {/* Right side */}
      <div className="navbar-right">
        <a href="https://github.com" target="_blank" rel="noreferrer"
          style={{ color: "var(--text-3)", display: "flex", alignItems: "center" }}
          aria-label="GitHub">
          <ExternalLink size={14} />
        </a>
        <div className="version-pill">
          <span className="version-dot" />
          v1.0
        </div>
      </div>
    </nav>
  );
}
