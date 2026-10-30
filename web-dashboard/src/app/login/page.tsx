"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../lib/auth-context";
import { AlertCircleIcon, HexagonIcon } from "../../components/Icons";
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
    <div className="mx-auto max-w-xl px-5 py-16">
      <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6 text-white">
        
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-white/20 bg-white/10 text-white shadow-xl">
            <HexagonIcon className="h-7 w-7" strokeWidth={1.5} />
          </div>
          <h1 className="text-2xl font-normal text-white">Sign in to SignalSafe Campus</h1>
          <p className="text-xs text-white/60">
            Authenticate using your campus email to scan links or access security operations.
          </p>
        </div>

        {isAuthenticated && (
          <div className="rounded-xl border border-white/20 bg-white/10 p-4 flex items-center justify-between text-xs">
            <div>
              <p className="font-mono text-xs uppercase tracking-wide font-semibold text-white">
                Active Session: {role?.toUpperCase()}
              </p>
              <p className="font-mono text-[10px] text-white/50">Authenticated via SSO</p>
            </div>
            <button
              onClick={logout}
              className="rounded-full border border-white/25 bg-white/10 px-3.5 py-1 text-xs font-mono uppercase tracking-[0.1em] text-white hover:bg-white/20"
            >
              Sign Out
            </button>
          </div>
        )}

        {/* Quick Demo Personas */}
        <div className="border-t border-b border-white/10 py-5 space-y-3">
          <p className="font-mono text-[10px] font-semibold text-white/50 uppercase tracking-[0.15em] text-center">
            One-Click Persona Evaluation
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            
            <button
              type="button"
              onClick={() => handleQuickDemoLogin("student", "a.sharma@campus.edu")}
              className="rounded-xl border border-white/15 bg-white/5 p-3 text-left hover:bg-white/15 transition-colors"
            >
              <p className="font-medium text-xs text-white">Student</p>
              <p className="font-mono text-[10px] text-white/50 truncate">a.sharma@campus.edu</p>
              <span className="inline-block mt-1 font-mono text-[9px] uppercase tracking-wider text-white/60">Scanner & Reports</span>
            </button>

            <button
              type="button"
              onClick={() => handleQuickDemoLogin("faculty", "k.ramanathan@campus.edu")}
              className="rounded-xl border border-white/15 bg-white/5 p-3 text-left hover:bg-white/15 transition-colors"
            >
              <p className="font-medium text-xs text-white">Faculty</p>
              <p className="font-mono text-[10px] text-white/50 truncate">k.ramanathan@campus.edu</p>
              <span className="inline-block mt-1 font-mono text-[9px] uppercase tracking-wider text-white/60">Faculty Member</span>
            </button>

            <button
              type="button"
              onClick={() => handleQuickDemoLogin("security_admin", "v.sen@campus.edu")}
              className="rounded-xl border border-white/30 bg-white/15 p-3 text-left hover:bg-white/25 transition-colors"
            >
              <p className="font-medium text-xs text-white">Security Admin</p>
              <p className="font-mono text-[10px] text-white/50 truncate">v.sen@campus.edu</p>
              <span className="inline-block mt-1 font-mono text-[9px] uppercase tracking-wider text-white">Full SOC Console</span>
            </button>

          </div>
        </div>

        {/* Manual Form */}
        <form onSubmit={handleCustomLogin} className="space-y-4">
          {errorMsg && (
            <div className="rounded-xl border border-red-400/30 bg-red-500/10 p-3 text-xs text-red-200 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div>
            <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
              Campus Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="username@campus.edu"
              required
              className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-xs text-white placeholder:text-white/40 focus:border-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
              Password / Token
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-xs text-white placeholder:text-white/40 focus:border-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
              Role Assignment
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(["student", "faculty", "security_admin"] as UserRole[]).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setSelectedRole(r)}
                  className={`py-2 px-2 rounded-lg text-xs font-mono uppercase tracking-[0.1em] border text-center transition-colors ${
                    selectedRole === r
                      ? "border-white bg-white text-black font-bold"
                      : "border-white/15 bg-white/5 text-white/70 hover:bg-white/10"
                  }`}
                >
                  {r === "security_admin" ? "Admin" : r}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded-full bg-white py-3 text-xs font-medium text-black hover:bg-white/85 disabled:bg-white/40 transition-colors shadow-lg mt-2"
          >
            {isSubmitting ? "Authenticating..." : "Sign In to Portal"}
          </button>
        </form>

        <div className="border-t border-white/10 pt-4 text-center">
          <p className="font-mono text-[10px] text-white/40 uppercase tracking-wide">
            Protected by Campus SSO • Never share your password or OTP.
          </p>
        </div>

      </div>
    </div>
  );
}
