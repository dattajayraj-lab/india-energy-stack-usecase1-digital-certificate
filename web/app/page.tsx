"use client";

import { BuildingIcon, ScanSearchIcon, WalletIcon } from "lucide-react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { useI18n, type MessageKey } from "@/lib/i18n";

const PORTALS: { href: string; title: MessageKey; body: MessageKey; icon: typeof WalletIcon }[] = [
  { href: "/wallet", title: "portal.consumer", body: "portal.consumer.body", icon: WalletIcon },
  { href: "/verifier", title: "portal.verifier", body: "portal.verifier.body", icon: ScanSearchIcon },
  { href: "/admin", title: "portal.admin", body: "portal.admin.body", icon: BuildingIcon },
];

export default function Home() {
  const { t } = useI18n();
  return (
    <AppShell>
      <section className="py-8">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{t("app.tagline")}</h1>
        <p className="mt-3 max-w-2xl text-muted-foreground">{t("app.intro")}</p>
      </section>
      <div className="grid gap-4 sm:grid-cols-3">
        {PORTALS.map(({ href, title, body, icon: Icon }) => (
          <Card key={href}>
            <CardHeader>
              <Icon className="mb-2 size-6 text-primary" aria-hidden />
              <CardTitle>{t(title)}</CardTitle>
              <CardDescription>{t(body)}</CardDescription>
            </CardHeader>
            <CardFooter className="mt-auto">
              <Link href={href} className={buttonVariants({ variant: "outline" })}>
                {t("portal.open")}: {t(title)}
              </Link>
            </CardFooter>
          </Card>
        ))}
      </div>
    </AppShell>
  );
}
