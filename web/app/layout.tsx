import type { Metadata } from "next";
import { Geist, Geist_Mono, Noto_Sans_Devanagari } from "next/font/google";
import { Providers } from "@/app/providers";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
const devanagari = Noto_Sans_Devanagari({ variable: "--font-devanagari", subsets: ["devanagari"] });

export const metadata: Metadata = {
  title: "Energy Passport",
  description: "IES Consumer Energy Passport: issue, hold, share and verify.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${geistSans.variable} ${geistMono.variable} ${devanagari.variable} font-sans antialiased`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
