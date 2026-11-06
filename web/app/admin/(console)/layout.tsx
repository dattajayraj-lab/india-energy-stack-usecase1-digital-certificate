"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { AppShell, type NavItem } from "@/components/app-shell";
import { clearSession, getSession } from "@/lib/api";

const NAV: NavItem[] = [
  { href: "/admin", label: "admin.nav.dashboard" },
  { href: "/admin/consumers", label: "admin.nav.consumers" },
  { href: "/admin/passports", label: "admin.nav.passports" },
  { href: "/admin/logs", label: "admin.nav.logs" },
];

export default function AdminLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (getSession("admin")) setReady(true);
    else router.replace("/admin/login");
  }, [router]);

  if (!ready) return null;
  return (
    <AppShell
      nav={NAV}
      onSignOut={() => {
        clearSession("admin");
        router.replace("/admin/login");
      }}
    >
      {children}
    </AppShell>
  );
}
