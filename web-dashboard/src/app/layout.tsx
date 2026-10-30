import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "../lib/auth-context";
import { Navigation } from "../components/Navigation";
import { Footer } from "../components/Footer";
import { BackgroundVideo } from "../components/BackgroundVideo";

export const metadata: Metadata = {
  title: "NOVA_AI — Today AI Aligns With Bold Dreams | SignalSafe Campus",
  description: "Institutional cybersecurity portal with dark cinematic AI intelligence for detecting phishing, scam URLs, fraudulent QR codes, and reporting digital threats.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen relative bg-[#0a0a0a] text-white font-sans antialiased selection:bg-white/20 selection:text-white">
        <AuthProvider>
          {/* Fixed scroll-scrubbed background video */}
          <BackgroundVideo />

          {/* Foreground content wrapper */}
          <div className="relative z-10 flex min-h-screen flex-col">
            <Navigation />
            <main className="flex-1 pb-16">{children}</main>
            <Footer />
          </div>
        </AuthProvider>
      </body>
    </html>
  );
}
