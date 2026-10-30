"use client";

import React, { createContext, useContext, useState, useEffect } from "react";
import { UserProfile, UserRole } from "./types";

interface AuthContextType {
  user: UserProfile | null;
  role: UserRole | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, role?: UserRole) => Promise<void>;
  logout: () => void;
  switchRole: (role: UserRole) => void;
}

const STUDENT_DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTAiLCJlbWFpbCI6ImEuc2hhcm1hQGNhbXB1cy5lZHUiLCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJpc3MiOiJodHRwczovL3htaHpxZXBjdHprdmJvdnVyeHZoLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJhcHBfbWV0YWRhdGEiOnsicm9sZSI6IlNUVURFTlQifSwiaWF0IjoxNzkzMzYxMDA2LCJleHAiOjIxMDg3MjEwMDZ9.GvU7zcESUXYCkWPpGKzEqeMYsOumWxTU1QQXCFCPymE";
const FACULTY_DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTEiLCJlbWFpbCI6ImsucmFtYW5hdGhhbkBjYW1wdXMuZWR1Iiwicm9sZSI6ImF1dGhlbnRpY2F0ZWQiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiaXNzIjoiaHR0cHM6Ly94bWh6cWVwY3R6a3Zib3Z1cnh2aC5zdXBhYmFzZS5jby9hdXRoL3YxIiwiYXBwX21ldGFkYXRhIjp7InJvbGUiOiJGQUNVTFRZIn0sImlhdCI6MTc5MzM2MTAwNiwiZXhwIjoyMTA4NzIxMDA2fQ.5eT5bseJC2-eQyGPhYE7rf4zcX4TZEBWwLLtQJFEpVo";
const ADMIN_DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTIiLCJlbWFpbCI6InYuc2VuQGNhbXB1cy5lZHUiLCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJpc3MiOiJodHRwczovL3htaHpxZXBjdHprdmJvdnVyeHZoLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJhcHBfbWV0YWRhdGEiOnsicm9sZSI6IkNBTVBVU19BRE1JTiJ9LCJpYXQiOjE3OTMzNjEwMDYsImV4cCI6MjEwODcyMTAwNn0.1Sw_TMRMbnIEoiiUxuqs-J-wGKoW1hAaEDaPumjqqz0";

const DEMO_USERS: Record<UserRole, UserProfile> = {
  student: {
    id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    email: "a.sharma@campus.edu",
    fullName: "Aarav Sharma",
    role: "student",
    campusId: "STU-2024-9182",
    department: "Computer Science & Engineering",
    token: STUDENT_DEV_TOKEN,
  },
  faculty: {
    id: "f1b2c3d4-e5f6-7890-abcd-ef1234567891",
    email: "k.ramanathan@campus.edu",
    fullName: "Dr. K. Ramanathan",
    role: "faculty",
    campusId: "FAC-1998-0412",
    department: "Information Technology",
    token: FACULTY_DEV_TOKEN,
  },
  security_admin: {
    id: "c1b2c3d4-e5f6-7890-abcd-ef1234567892",
    email: "v.sen@campus.edu",
    fullName: "Vikram Sen",
    role: "security_admin",
    campusId: "SEC-2020-0019",
    department: "Campus Incident Response Team (CIRT)",
    token: ADMIN_DEV_TOKEN,
  },
};

const AuthContext = createContext<AuthContextType>({
  user: null,
  role: null,
  isAuthenticated: false,
  isLoading: true,
  login: async () => {},
  logout: () => {},
  switchRole: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Default to student for accessible evaluation, persisted in localStorage
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("signalsafe_user");
      if (stored) {
        const parsed = JSON.parse(stored);
        // Ensure token is attached if missing from legacy store
        if (!parsed.token && DEMO_USERS[parsed.role as UserRole]?.token) {
          parsed.token = DEMO_USERS[parsed.role as UserRole].token;
          parsed.id = DEMO_USERS[parsed.role as UserRole].id;
        }
        setUser(parsed);
        localStorage.setItem("signalsafe_user", JSON.stringify(parsed));
        if (parsed.token) localStorage.setItem("signalsafe_token", parsed.token);
      } else {
        // Default demo session
        const defaultUser = DEMO_USERS.student;
        setUser(defaultUser);
        localStorage.setItem("signalsafe_user", JSON.stringify(defaultUser));
        if (defaultUser.token) localStorage.setItem("signalsafe_token", defaultUser.token);
      }
    } catch {
      setUser(DEMO_USERS.student);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, chosenRole?: UserRole) => {
    setIsLoading(true);
    let targetRole: UserRole = chosenRole || "student";
    if (!chosenRole) {
      if (email.includes("admin") || email.includes("sec")) {
        targetRole = "security_admin";
      } else if (email.includes("prof") || email.includes("dr") || email.includes("faculty")) {
        targetRole = "faculty";
      }
    }

    const template = DEMO_USERS[targetRole];
    const loggedInUser: UserProfile = {
      ...template,
      email,
      fullName: email.split("@")[0].replace(".", " ").toUpperCase(),
    };

    setUser(loggedInUser);
    localStorage.setItem("signalsafe_user", JSON.stringify(loggedInUser));
    if (loggedInUser.token) localStorage.setItem("signalsafe_token", loggedInUser.token);
    setIsLoading(false);
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("signalsafe_user");
    localStorage.removeItem("signalsafe_token");
  };

  const switchRole = (newRole: UserRole) => {
    const newUser = DEMO_USERS[newRole];
    setUser(newUser);
    localStorage.setItem("signalsafe_user", JSON.stringify(newUser));
    if (newUser.token) localStorage.setItem("signalsafe_token", newUser.token);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        role: user?.role || null,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        switchRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
