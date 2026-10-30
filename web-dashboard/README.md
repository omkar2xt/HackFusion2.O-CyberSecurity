# SignalSafe Campus — Web Dashboard (Developer 3)

The primary user and campus-admin portal for **SignalSafe Campus**, an institutional cybersecurity solution designed to help campus users recognize, resist, and report digital threats.

---

## 🚀 Features Implemented

| ID | Feature | Implementation Highlights | Status |
| :--- | :--- | :--- | :--- |
| **WD-01** | **Application Shell** | Next.js 14 App Router, TypeScript, responsive layout, bespoke SVG icons, institutional color palette, skeleton loaders. | ✅ Complete |
| **WD-02** | **Authentication UI** | Role-aware navigation (Student / Faculty / Security Admin), one-click demo persona switcher, SSO simulation. | ✅ Complete |
| **WD-03** | **Student/Faculty Scanner** | Multi-modal threat scanner for URLs and message text. Interactive presets, 0-100 risk gauge, explainable indicators, and 1-click escalation. | ✅ Complete |
| **WD-04** | **Incident Submission** | Intake wizard for threats (phishing, quishing, payment fraud, cyberbullying), file upload simulation, anonymity toggle, reference code generation (`SSC-2026-XXXX`). | ✅ Complete |
| **WD-05** | **My Reports** | Personal case tracking with status filtering, narrative inspection, linked scan summaries, and milestone tracker. | ✅ Complete |
| **WD-06** | **Admin Dashboard** | Security Operations Center (SOC) KPI metrics, severity distribution, threat category distribution, and live audit telemetry. | ✅ Complete |
| **WD-07** | **Incident Queue** | Case triage pipeline with multi-field search, status filters (`NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`), and severity filters. | ✅ Complete |
| **WD-08** | **Incident Detail** | Detailed forensic case view, cryptographic evidence vault, reporter anonymity protection, and linked heuristic scan verdicts. | ✅ Complete |
| **WD-09** | **Case Management** | Admin action box to adjust case status, modify severity, assign CIRT officers, and append internal investigation notes. | ✅ Complete |
| **WD-10** | **Audit Visibility** | Immutable event timeline logging all case status changes, assignments, notes, and timestamps. | ✅ Complete |

---

## 🛠️ Tech Stack & Architecture

- **Framework:** Next.js 14 (App Router) + React 18 + TypeScript
- **Styling:** Tailwind CSS (Refined institutional palette: deep slate `#0f172a`, off-white canvas `#f8fafc`, crisp borders, zero AI-tell clichés)
- **API Client:** Centralized typed client in `src/services/api.ts` connecting to the FastAPI backend at `/api/v1/` with a seamless local heuristic fallback for standalone testing.
- **Auth & RBAC:** Supabase Auth client ready with client-side role guards protecting `/admin/*` routes.
- **Compliance:** Includes complete Terms of Service (`/terms`) and Privacy Policy (`/privacy`).

---

## 📋 Getting Started

### 1. Install Dependencies
```bash
cd web-dashboard
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env.local`:
```bash
cp .env.example .env.local
```

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Hackathon Demo Guide

1. **Test Threat Scanner (`/scan`):**
   - Click one of the quick test presets (e.g. *Malicious: Fake Mess Refund Phishing*).
   - Click **Run Security Scan** to inspect the 0-100 risk score, explainable indicators, and safety recommendations.
   - Click **Escalate to Security Incident Report** to automatically transfer the scan into a formal report.
2. **Submit Incident Report (`/report`):**
   - Choose incident category, set severity, optionally toggle **Submit anonymously**, and click **Submit Incident Report**.
   - Note the generated reference number (e.g., `SSC-2026-8941`).
3. **Check Reporter History (`/my-reports`):**
   - View submitted reports, filter by status, and click **View Details** to inspect investigation progress.
4. **Evaluate Admin SOC Console (`/admin` and `/admin/incidents`):**
   - Use the **Role Switcher** in the top navigation bar to switch to **Security Admin**.
   - Review total incidents, severity breakdown, and threat categories.
   - Navigate to `/admin/incidents` to filter cases by status or severity.
   - Click **Investigate →** on any case to open `/admin/incidents/[id]`.
   - Update the status (e.g., move to `INVESTIGATING` or `RESOLVED`), change severity, add an investigation note, and observe the new entry added to the immutable audit timeline!
