import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Adversarial API Security Fuzzer",
  description: "Red Team + Blue Team automated API vulnerability scanner",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-gray-100 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
