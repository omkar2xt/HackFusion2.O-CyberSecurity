"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../lib/auth-context";
import { LockIcon, AlertCircleIcon } from "../../components/Icons";
import { UserRole } from "../../lib/types";

export default function LoginPage() {
  const router = useRouter();
  const { login, role, isAuthenticated, logout } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [selectedRole, setSelectedRole] = useState<UserRole>("student");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setErrorMsg("Please provide your institutional email address.");
      return;
    }
    setErrorMsg("");
    setIsSubmitting(true);
    try {
      await login(email, selectedRole);
      if (selectedRole === "security_admin") {
        router.push("/admin");
      } else {
        router.push("/scan");
      }
    } catch {
      setErrorMsg("Failed to authenticate. Please verify your credentials.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickDemoLogin = async (presetRole: UserRole, presetEmail: string) => {
    setIsSubmitting(true);
    await login(presetEmail, presetRole);
    setIsSubmitting(false);
    if (presetRole === "security_admin") {
      router.push("/admin");
    } else {
      router.push("/scan");
    }
  };

  return (
    <div className="mx-auto max-w-xl px-4 py-12">
      <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-xs space-y-6">
        
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg bg-slate-900 text-white">
            <LockIcon className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-bold text-slate-900">Sign in to SignalSafe Campus</h1>
          <p className="text-xs text-slate-500">
            Authenticate using your campus email to scan links or access security operations.
          </p>
        </div>

        {isAuthenticated && (
          <div className="rounded border border-blue-200 bg-blue-50/70 p-3 flex items-center justify-between text-xs text-blue-900">
            <div>
              <p className="font-semibold">Currently signed in as: {role?.toUpperCase()}</p>
              <p className="text-[11px] text-blue-700">You already have an active session.</p>
            </div>
            <button
              onClick={logout}
              className="px-2.5 py-1 bg-white border border-blue-300 rounded font-semibold text-blue-800 hover:bg-blue-100/50"
            >
              Sign Out
            </button>
          </div>
        )}

        {/* Quick Demo Personas - Perfect for Hackathon Testing */}
        <div className="border-t border-b border-slate-100 py-4 space-y-3">
          <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider text-center">
            One-Click Evaluation Personas
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            
            <button
              type="button"
              onClick={() => handleQuickDemoLogin("student", "a.sharma@campus.edu")}
              className="border border-slate-200 hover:border-slate-400 bg-slate-50/50 p-2.5 rounded text-left transition-colors"
            >
              <p className="font-semibold text-xs text-slate-900">Student</p>
              <p className="text-[11px] text-slate-500 truncate">a.sharma@campus.edu</p>
              <span className="inline-block mt-1 text-[10px] text-slate-500 font-medium">Scanner & My Reports</span>
            </button>

            <button
              type="button"
              onClick={() => handleQuickDemoLogin("faculty", "k.ramanathan@campus.edu")}
              className="border border-slate-200 hover:border-slate-400 bg-slate-50/50 p-2.5 rounded text-left transition-colors"
            >
              <p className="font-semibold text-xs text-slate-900">Faculty</p>
              <p className="text-[11px] text-slate-500 truncate">k.ramanathan@campus.edu</p>
              <span className="inline-block mt-1 text-[10px] text-slate-500 font-medium">Faculty Member</span>
            </button>

            <button
              type="button"
              onClick={() => handleQuickDemoLogin("security_admin", "v.sen@campus.edu")}
              className="border border-blue-200 hover:border-blue-400 bg-blue-50/40 p-2.5 rounded text-left transition-colors"
            >
              <p className="font-semibold text-xs text-blue-900">Security Admin</p>
              <p className="text-[11px] text-blue-700 truncate">v.sen@campus.edu</p>
              <span className="inline-block mt-1 text-[10px] text-blue-600 font-medium">Full SOC Operations</span>
            </button>

          </div>
        </div>

        {/* Manual Form */}
        <form onSubmit={handleCustomLogin} className="space-y-4">
          {errorMsg && (
            <div className="rounded border border-red-200 bg-red-50 p-2.5 text-xs text-red-800 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Campus Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="username@campus.edu"
              required
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Password / Token
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Select Role Assignment
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(["student", "faculty", "security_admin"] as UserRole[]).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setSelectedRole(r)}
                  className={`py-1.5 px-2 rounded text-xs font-medium border text-center capitalize transition-colors ${
                    selectedRole === r
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                  }`}
                >
                  {r === "security_admin" ? "Security Admin" : r}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded bg-slate-900 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-xs"
          >
            {isSubmitting ? "Authenticating..." : "Sign In to Portal"}
          </button>
        </form>

        {/* Security notice */}
        <div className="border-t border-slate-100 pt-4 text-center">
          <p className="text-[11px] text-slate-500">
            Protected by Campus Identity SSO • Never share your password or OTP with anyone.
          </p>
        </div>

      </div>
    </div>
  );
}
