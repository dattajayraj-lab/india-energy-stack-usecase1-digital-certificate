"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { AppShell, type NavItem } from "@/components/app-shell";
import { clearSession, getSession } from "@/lib/api";

const NAV: NavItem[] = [
  { href: "/wallet", label: "wallet.nav.passport" },
  { href: "/wallet/share", label: "wallet.nav.share" },
  { href: "/wallet/history", label: "wallet.nav.history" },
];

export default function WalletLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (getSession("consumer")) setReady(true);
    else router.replace("/wallet/login");
  }, [router]);

  if (!ready) return null;
  return (
    <AppShell
      nav={NAV}
      onSignOut={() => {
        clearSession("consumer");
        router.replace("/wallet/login");
      }}
    >
      {children}
    </AppShell>
  );
}
