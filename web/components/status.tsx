"use client";

import { BanIcon, CheckCircle2Icon, CircleDashedIcon, InfoIcon, TriangleAlertIcon, XCircleIcon } from "lucide-react";
import type { ComponentType } from "react";
import { Badge } from "@/components/ui/badge";
import { useI18n, type MessageKey } from "@/lib/i18n";

type Tone = "good" | "warn" | "bad" | "muted";

const TONE: Record<Tone, { variant: "default" | "secondary" | "destructive" | "outline"; icon: ComponentType<{ className?: string }> }> = {
  good: { variant: "default", icon: CheckCircle2Icon },
  warn: { variant: "outline", icon: TriangleAlertIcon },
  bad: { variant: "destructive", icon: XCircleIcon },
  muted: { variant: "secondary", icon: CircleDashedIcon },
};

/** State always carries an icon and a word, never colour alone. */
export function StateBadge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  const { variant, icon: Icon } = TONE[tone];
  return (
    <Badge variant={variant}>
      <Icon className="size-3" aria-hidden />
      {children}
    </Badge>
  );
}

export function PassportStatus({ status }: { status: string | null | undefined }) {
  const { t } = useI18n();
  if (status === "active") return <StateBadge tone="good">{t("status.active")}</StateBadge>;
  if (status === "revoked") {
    return (
      <Badge variant="destructive">
        <BanIcon className="size-3" aria-hidden />
        {t("status.revoked")}
      </Badge>
    );
  }
  return <StateBadge tone="muted">{t("status.none")}</StateBadge>;
}

export function InspectionStatus({ status }: { status: string }) {
  const { t } = useI18n();
  const tone: Tone = status === "pass" ? "good" : status === "fail" ? "bad" : status === "conditional" ? "warn" : "muted";
  return <StateBadge tone={tone}>{t(`inspection.${status}` as MessageKey)}</StateBadge>;
}

export function CheckStatus({ status }: { status: "pass" | "fail" | "warn" | "skip" }) {
  const { t } = useI18n();
  if (status === "warn") {
    return (
      <Badge variant="outline">
        <InfoIcon className="size-3" aria-hidden />
        {t("checkStatus.warn")}
      </Badge>
    );
  }
  const tone: Tone = status === "pass" ? "good" : status === "fail" ? "bad" : "muted";
  return <StateBadge tone={tone}>{t(`checkStatus.${status}` as MessageKey)}</StateBadge>;
}
