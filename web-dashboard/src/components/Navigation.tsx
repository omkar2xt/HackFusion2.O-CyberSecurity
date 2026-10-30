"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "../lib/auth-context";
import {
  ShieldIcon,
  ScanIcon,
  AlertCircleIcon,
  FileTextIcon,
  ActivityIcon,
  LockIcon,
  BellIcon,
  BookOpenIcon,
} from "./Icons";
import { UserRole } from "../lib/types";

export function Navigation() {
  const pathname = usePathname();
  const { user, role, switchRole, logout, isAuthenticated } = useAuth();
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isActive = (path: string) => {
    if (path === "/admin") return pathname === "/admin";
    if (path.startsWith("/admin/incidents")) return pathname.startsWith("/admin/incidents");
    return pathname === path;
  };

  const navLinks = [
    { href: "/scan", label: "Threat Scanner", icon: ScanIcon },
    { href: "/advisories", label: "Advisories", icon: BellIcon },
    { href: "/resources", label: "Guidelines", icon: BookOpenIcon },
    { href: "/report", label: "Report Incident", icon: AlertCircleIcon },
    { href: "/my-reports", label: "My Reports", icon: FileTextIcon },
  ];

  const adminLinks = [
    { href: "/admin", label: "SOC Overview", icon: ActivityIcon },
    { href: "/admin/incidents", label: "Incident Queue", icon: ShieldIcon },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200 bg-white/95 backdrop-blur-xs">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        
        {/* Brand identity */}
        <div className="flex items-center gap-6 lg:gap-8">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-slate-900 text-white shadow-xs group-hover:bg-slate-800 transition-colors">
              <ShieldIcon className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-900 tracking-tight text-base">SignalSafe</span>
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-700 border border-slate-200">
                  Campus
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-normal">Cyber Threat Response</p>
            </div>
          </Link>

          {/* Primary Navigation Desktop */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((item) => {
              const active = isActive(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-md transition-colors ${
                    active
                      ? "bg-slate-100 text-slate-900"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.label}</span>
                </Link>
              );
            })}

            {/* Admin section for security admin */}
            {role === "security_admin" && (
              <div className="ml-2 pl-2 border-l border-slate-200 flex items-center gap-1">
                {adminLinks.map((item) => {
                  const active = isActive(item.href);
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold rounded-md transition-colors ${
                        active
                          ? "bg-blue-50 text-blue-900 border border-blue-200"
                          : "text-blue-700 hover:bg-blue-50/70"
                      }`}
                    >
                      <Icon className="h-3.5 w-3.5 text-blue-600" />
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            )}
          </nav>
        </div>

        {/* Right tools: Role Switcher Demo Control & User Account */}
        <div className="flex items-center gap-3">
          
          {/* Quick interactive Role Switcher for Evaluation */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
              className="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 shadow-2xs"
              title="Switch demo persona to test both user and admin views"
            >
              <span className="text-slate-400">Role:</span>
              <span className={`capitalize font-semibold ${
                role === "security_admin" ? "text-blue-700" : "text-slate-900"
              }`}>
                {role === "security_admin" ? "Security Admin" : role || "Guest"}
              </span>
              <svg className="h-3.5 w-3.5 text-slate-500" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>

            {roleDropdownOpen && (
              <div className="absolute right-0 mt-2 w-56 rounded-md border border-slate-200 bg-white py-1 shadow-lg z-50">
                <div className="px-3 py-2 border-b border-slate-100">
                  <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Demo Persona Switch</p>
                  <p className="text-xs text-slate-600 mt-0.5">Toggle perspectives to evaluate access controls.</p>
                </div>
                {(["student", "faculty", "security_admin"] as UserRole[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => {
                      switchRole(r);
                      setRoleDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between ${
                      role === r ? "bg-slate-100 font-semibold text-slate-900" : "text-slate-700 hover:bg-slate-50"
                    }`}
                  >
                    <span className="capitalize">{r === "security_admin" ? "Security Officer / Admin" : r}</span>
                    {role === r && <span className="text-blue-600 font-bold">Active</span>}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* User state / Login Button */}
          {isAuthenticated && user ? (
            <div className="hidden sm:flex items-center gap-3 pl-2 border-l border-slate-200">
              <div className="text-right">
                <p className="text-xs font-semibold text-slate-800 leading-none">{user.fullName}</p>
                <p className="text-[11px] text-slate-500 mt-0.5">{user.campusId}</p>
              </div>
              <button
                onClick={logout}
                className="text-xs font-medium text-slate-500 hover:text-slate-800 underline underline-offset-2"
              >
                Sign out
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 transition-colors"
            >
              <LockIcon className="h-3.5 w-3.5" />
              Sign in
            </Link>
          )}

          {/* Mobile menu trigger */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-md text-slate-600 hover:bg-slate-100"
            aria-label="Toggle Navigation"
          >
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              {mobileMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-200 bg-white px-4 pt-2 pb-4 space-y-1">
          {navLinks.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileMenuOpen(false)}
              className={`block px-3 py-2 rounded-md text-sm font-medium ${
                isActive(item.href) ? "bg-slate-100 text-slate-900" : "text-slate-600 hover:bg-slate-50"
              }`}
            >
              {item.label}
            </Link>
          ))}
          {role === "security_admin" && (
            <div className="pt-2 border-t border-slate-100">
              <p className="px-3 text-xs font-semibold text-slate-400 uppercase mb-1">SOC Controls</p>
              {adminLinks.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`block px-3 py-2 rounded-md text-sm font-medium ${
                    isActive(item.href) ? "bg-blue-50 text-blue-900" : "text-blue-700 hover:bg-blue-50/50"
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>
          )}
        </div>
      )}
    </header>
  );
}
