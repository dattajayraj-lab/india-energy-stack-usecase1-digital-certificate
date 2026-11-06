"use client";

import { LogOutIcon, MoonIcon, ShieldCheckIcon, SunIcon } from "lucide-react";
import { useTheme } from "next-themes";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { useI18n, type MessageKey } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export interface NavItem {
  href: string;
  label: MessageKey;
}

export function AppShell({
  nav = [],
  onSignOut,
  children,
}: {
  nav?: NavItem[];
  onSignOut?: () => void;
  children: ReactNode;
}) {
  const { t, toggle } = useI18n();
  const { resolvedTheme, setTheme } = useTheme();
  const pathname = usePathname();

  return (
    <div className="min-h-dvh bg-background">
      <header className="sticky top-0 z-20 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-5xl items-center gap-2 px-4">
          <Link href="/" className="flex items-center gap-2 font-semibold">
            <ShieldCheckIcon className="size-5 text-primary" aria-hidden />
            <span className="hidden sm:inline">{t("app.name")}</span>
          </Link>
          <div className="ml-auto flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={toggle}>
              {t("nav.language")}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label={t("nav.toggleTheme")}
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            >
              <SunIcon className="hidden size-4 dark:block" aria-hidden />
              <MoonIcon className="size-4 dark:hidden" aria-hidden />
            </Button>
            {onSignOut && (
              <Button variant="ghost" size="icon" aria-label={t("nav.signOut")} onClick={onSignOut}>
                <LogOutIcon className="size-4" aria-hidden />
              </Button>
            )}
          </div>
        </div>
        {nav.length > 0 && (
          <nav className="mx-auto flex max-w-5xl gap-1 overflow-x-auto px-4 pb-2">
            {nav.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={pathname === item.href ? "page" : undefined}
                className={cn(
                  "shrink-0 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground",
                  pathname === item.href && "bg-muted font-medium text-foreground",
                )}
              >
                {t(item.label)}
              </Link>
            ))}
          </nav>
        )}
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">{children}</main>
    </div>
  );
}
