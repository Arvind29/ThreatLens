import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "ThreatLens by LensLabs", description: "Multi-source threat intelligence search, simplified." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
