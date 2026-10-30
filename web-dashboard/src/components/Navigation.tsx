"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "../lib/auth-context";
import { apiClient } from "../services/api";
import { HexagonIcon, ScanIcon, AlertCircleIcon, FileTextIcon, ActivityIcon, ShieldIcon } from "./Icons";
import { UserRole } from "../lib/types";

export function Navigation() {
  const pathname = usePathname();
  const { user, role, switchRole, logout, isAuthenticated } = useAuth();
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [backendStatus, setBackendStatus] = useState<"checking" | "connected" | "offline">("checking");

  useEffect(() => {
    let mounted = true;
    apiClient.checkHealth().then((res) => {
      if (mounted) setBackendStatus(res ? "connected" : "offline");
    });
    const interval = setInterval(() => {
      apiClient.checkHealth().then((res) => {
        if (mounted) setBackendStatus(res ? "connected" : "offline");
      });
    }, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const isActive = (path: string) => {
    if (path === "/admin") return pathname === "/admin";
    if (path.startsWith("/admin/incidents")) return pathname.startsWith("/admin/incidents");
    return pathname === path;
  };

  const navLinks = [
    { href: "/scan", label: "Threat Scanner", icon: ScanIcon },
    { href: "/report", label: "Report Incident", icon: AlertCircleIcon },
    { href: "/my-reports", label: "My Reports", icon: FileTextIcon },
  ];

  const adminLinks = [
    { href: "/admin", label: "SOC Console", icon: ActivityIcon },
    { href: "/admin/incidents", label: "Incident Queue", icon: ShieldIcon },
  ];

  const handleAdminNavClick = () => {
    if (role !== "security_admin") {
      switchRole("security_admin");
    }
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/15 bg-[#0a0a0a]/60 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5 sm:px-8 md:px-12">
        
        {/* Brand identity: Hexagon + novaai | SignalSafe */}
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-2.5 group">
            <HexagonIcon className="h-6 w-6 text-white group-hover:rotate-12 transition-transform duration-300" strokeWidth={1.5} />
            <div className="flex items-baseline gap-2">
              <span className="text-lg sm:text-xl font-medium tracking-tight text-white drop-shadow-sm">novaai</span>
              <span className="font-mono text-[10px] tracking-[0.15em] uppercase text-white/60">/ signalsafe</span>
            </div>
          </Link>

          {/* Navigation Links Desktop */}
          <nav className="hidden md:flex items-center gap-5 lg:gap-7">
            {navLinks.map((item) => {
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`text-sm tracking-wide transition-colors ${
                    active
                      ? "text-white font-medium drop-shadow-md"
                      : "text-white/70 hover:text-white"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}

            {/* Admin / SOC Controls: Always visible for evaluation */}
            <div className="ml-1 pl-4 border-l border-white/20 flex items-center gap-3">
              <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-white/40 hidden xl:inline">
                SOC
              </span>
              {adminLinks.map((item) => {
                const active = isActive(item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={handleAdminNavClick}
                    className={`text-xs font-mono uppercase tracking-[0.12em] transition-all rounded-lg px-2.5 py-1 ${
                      active
                        ? "text-white bg-white/20 border border-white/30 backdrop-blur-md font-semibold"
                        : "text-white/70 hover:text-white hover:bg-white/10 border border-white/10"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </nav>
        </div>

        {/* Right Action Tools: Backend status, Role Switcher & Glass Profile/Auth */}
        <div className="flex items-center gap-3">
          
          {/* Live API Health Status Badge */}
          <div
            className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/10 bg-white/5 font-mono text-[10px] tracking-wider uppercase text-white/70"
            title={
              backendStatus === "connected"
                ? "Connected to SignalSafe FastAPI backend (http://localhost:8000/api/v1)"
                : backendStatus === "checking"
                ? "Checking backend service connectivity..."
                : "Backend service unreachable - running in heuristic fallback mode"
            }
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                backendStatus === "connected"
                  ? "bg-emerald-400 animate-pulse"
                  : backendStatus === "checking"
                  ? "bg-amber-400"
                  : "bg-white/40"
              }`}
            />
            <span>{backendStatus === "connected" ? "Backend Online" : backendStatus === "checking" ? "Connecting" : "Backend Offline"}</span>
          </div>

          {/* Persona Switcher with Left-Accent Glass Badge */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
              className="inline-flex items-center gap-2 border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md font-mono text-[11px] uppercase tracking-[0.15em] text-white/90 hover:bg-white/25 transition-colors"
              title="Toggle demo persona to test both user and admin access"
            >
              <span className="text-white/50">ROLE:</span>
              <span className="font-semibold text-white">
                {role === "security_admin" ? "ADMIN" : role?.toUpperCase() || "STUDENT"}
              </span>
              <svg className="h-3 w-3 text-white/60 ml-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>

            {roleDropdownOpen && (
              <div className="absolute right-0 mt-2 w-56 rounded-xl border border-white/20 bg-[#0a0a0a]/90 backdrop-blur-xl p-1.5 shadow-2xl z-50">
                <div className="px-3 py-2 border-b border-white/10">
                  <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Persona Selection</p>
                  <p className="text-xs text-white/80 mt-0.5">Toggle perspectives to evaluate access controls.</p>
                </div>
                {(["student", "faculty", "security_admin"] as UserRole[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => {
                      switchRole(r);
                      setRoleDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono uppercase tracking-[0.1em] flex items-center justify-between transition-colors ${
                      role === r
                        ? "bg-white/20 text-white font-bold"
                        : "text-white/70 hover:bg-white/10 hover:text-white"
                    }`}
                  >
                    <span>{r === "security_admin" ? "Security Admin" : r}</span>
                    {role === r && <span className="text-[10px] text-white">●</span>}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* User Sign In / Profile */}
          {isAuthenticated && user ? (
            <div className="hidden sm:flex items-center gap-3 pl-3 border-l border-white/15">
              <div className="text-right">
                <p className="text-xs font-medium text-white drop-shadow-sm leading-none">{user.fullName}</p>
                <p className="font-mono text-[10px] text-white/50 tracking-[0.1em] mt-0.5">{user.campusId}</p>
              </div>
              <button
                onClick={logout}
                className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60 hover:text-white"
              >
                Sign out
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="rounded-full bg-white px-4 py-2 text-xs font-medium text-black hover:bg-white/85 transition-colors"
            >
              Sign In
            </Link>
          )}

          {/* Mobile menu trigger */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-lg border border-white/15 bg-white/10 backdrop-blur-md text-white"
            aria-label="Toggle Navigation"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              {mobileMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-white/15 bg-[#0a0a0a]/95 backdrop-blur-xl px-5 pt-3 pb-5 space-y-2">
          <p className="px-3 font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 mb-1">Navigation</p>
          {navLinks.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileMenuOpen(false)}
              className={`block px-3 py-2 rounded-lg text-sm font-medium ${
                isActive(item.href) ? "bg-white/20 text-white" : "text-white/70 hover:bg-white/10"
              }`}
            >
              {item.label}
            </Link>
          ))}
          <div className="pt-2 border-t border-white/10">
            <p className="px-3 font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 mb-1">SOC Controls</p>
            {adminLinks.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => {
                  handleAdminNavClick();
                  setMobileMenuOpen(false);
                }}
                className={`block px-3 py-2 rounded-lg text-xs font-mono uppercase tracking-[0.1em] ${
                  isActive(item.href) ? "bg-white/20 text-white font-bold" : "text-white/80 hover:bg-white/10"
                }`}
              >
                {item.label}
              </Link>
            ))}
          </div>
        </div>
      )}
    </header>
  );
}
