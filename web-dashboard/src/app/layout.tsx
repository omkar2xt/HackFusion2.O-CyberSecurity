import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "../lib/auth-context";
import { Navigation } from "../components/Navigation";
import { Footer } from "../components/Footer";

export const metadata: Metadata = {
  title: "SignalSafe Campus | Threat Recognition & Incident Response",
  description: "Institutional cybersecurity portal for detecting phishing, scam URLs, fraudulent QR codes, and reporting digital threats.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col bg-slate-50 text-slate-900 font-sans antialiased">
        <AuthProvider>
          <Navigation />
          <main className="flex-1 pb-16">{children}</main>
          <Footer />
        </AuthProvider>
      </body>
    </html>
  );
}
