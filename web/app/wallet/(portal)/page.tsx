"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { InspectionStatus, PassportStatus } from "@/components/status";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { api, getSession, type IssueResult, type Passport, type PassportDetail } from "@/lib/api";
import { formatDate, useI18n, type MessageKey } from "@/lib/i18n";
import { parseCredential } from "@/lib/sdjwt";
import { loadCredential, proveControl, saveCredential, walletDid } from "@/lib/wallet";

const ASSET_LABELS: Record<string, string> = {
  SOLAR_PV: "Rooftop solar",
  BESS: "Battery",
  EV_CHARGER: "EV charger",
  INVERTER: "Inverter",
};

async function holderProof() {
  const nonce = await api<{ nonce: string; audience: string }>("/passports/nonce", {
    method: "POST",
    portal: "consumer",
  });
  return {
    holder_did: await walletDid(),
    holder_proof: await proveControl(nonce.nonce, nonce.audience),
  };
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium">{children}</dd>
    </div>
  );
}

export default function MyPassport() {
  const { t, locale } = useI18n();
  const queryClient = useQueryClient();
  const consumerNo = getSession("consumer")?.subject ?? "";
  const [consent, setConsent] = useState(false);

  const passports = useQuery({
    queryKey: ["mine"],
    queryFn: () => api<Passport[]>("/passports/mine", { portal: "consumer" }),
  });
  const current = passports.data?.find((p) => p.status === "active");
  const pending = passports.data?.some((p) => p.reissue_pending) ?? false;

  const detail = useQuery({
    queryKey: ["passport", current?.id],
    enabled: !!current,
    queryFn: () => api<PassportDetail>(`/passports/${current?.id}`, { portal: "consumer" }),
  });

  const local = useQuery({
    queryKey: ["local-credential", consumerNo, current?.credential_id],
    queryFn: async () => {
      const stored = await loadCredential(consumerNo);
      if (!stored || stored.credentialId !== current?.credential_id) return null;
      const parsed = await parseCredential(stored.token);
      return { name: parsed.nodes.find((n) => n.name === "fullName")?.value as string | undefined };
    },
  });

  const obtain = useMutation({
    mutationFn: async () => {
      const proof = await holderProof();
      const result = current
        ? await api<IssueResult>(`/passports/${current.id}/reissue`, {
            method: "POST",
            portal: "consumer",
            body: { ...proof, reason: "holder_rebind" },
          })
        : await api<IssueResult>("/passports/issue", {
            method: "POST",
            portal: "consumer",
            body: { ...proof, consent: true },
          });
      await saveCredential(consumerNo, result.passport.credential_id, result.credential as string);
    },
    onSuccess: () => {
      toast.success(t("wallet.issued"));
      queryClient.invalidateQueries();
    },
    onError: (error) => toast.error(error.message),
  });

  if (passports.isLoading) return <Skeleton className="h-64 w-full" />;

  if (!current) {
    return (
      <Card className="mx-auto max-w-lg">
        <CardHeader>
          <CardTitle>{pending ? t("wallet.pending.title") : t("wallet.none.title")}</CardTitle>
          <CardDescription>{pending ? t("wallet.pending.body") : t("wallet.none.body")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-start gap-2">
            <Checkbox id="consent" checked={consent} onCheckedChange={(value) => setConsent(value === true)} />
            <Label htmlFor="consent" className="leading-snug font-normal">
              {t("wallet.consent")}
            </Label>
          </div>
          <Button disabled={!consent || obtain.isPending} onClick={() => obtain.mutate()}>
            {pending ? t("wallet.collect") : t("wallet.get")}
          </Button>
        </CardContent>
      </Card>
    );
  }

  const connection = detail.data?.connection;
  return (
    <div className="grid gap-4">
      {local.isSuccess && local.data === null && (
        <Alert>
          <AlertTitle>{t("wallet.claim.title")}</AlertTitle>
          <AlertDescription className="grid gap-3">
            <p>{t("wallet.claim.body")}</p>
            <Button className="w-fit" disabled={obtain.isPending} onClick={() => obtain.mutate()}>
              {t("wallet.claim")}
            </Button>
          </AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-2">
            <div>
              <CardTitle>{local.data?.name ?? t("wallet.nav.passport")}</CardTitle>
              <CardDescription>
                {t("login.consumerNo")}: {consumerNo}
              </CardDescription>
            </div>
            <PassportStatus status={current.status} />
          </div>
        </CardHeader>
        <CardContent>
          <dl className="divide-y">
            <Row label={t("wallet.issuedOn")}>{formatDate(current.issued_at, locale)}</Row>
            <Row label={t("wallet.validUntil")}>{formatDate(current.expires_at, locale)}</Row>
            <Row label={t("wallet.version")}>{current.version}</Row>
          </dl>
        </CardContent>
      </Card>
      {connection && (
        <Card>
          <CardContent>
            <Accordion multiple defaultValue={["connection", "assets"]}>
              <AccordionItem value="connection">
                <AccordionTrigger>{t("wallet.connection")}</AccordionTrigger>
                <AccordionContent>
                  <dl className="divide-y">
                    <Row label={t("field.serviceConn")}>{connection.service_conn_no}</Row>
                    <Row label={t("field.tariff")}>{connection.tariff_category}</Row>
                    <Row label={t("field.load")}>{connection.sanctioned_load_kw} kW</Row>
                  </dl>
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="meters">
                <AccordionTrigger>{t("wallet.meters")}</AccordionTrigger>
                <AccordionContent>
                  <dl className="divide-y">
                    {connection.meters.map((meter) => (
                      <Row key={meter.meter_did} label={t(`meter.${meter.type}` as MessageKey)}>
                        {meter.meter_no}
                      </Row>
                    ))}
                  </dl>
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="assets">
                <AccordionTrigger>{t("wallet.assets")}</AccordionTrigger>
                <AccordionContent>
                  {connection.assets.length === 0 ? (
                    <p className="text-sm text-muted-foreground">{t("wallet.noAssets")}</p>
                  ) : (
                    <ul className="divide-y">
                      {connection.assets.map((asset) => (
                        <li key={asset.asset_did} className="flex items-center justify-between gap-3 py-2 text-sm">
                          <span>
                            <span className="font-medium">{ASSET_LABELS[asset.asset_type] ?? asset.asset_type}</span>
                            {asset.capacity_kw !== null && (
                              <span className="text-muted-foreground"> · {asset.capacity_kw} kW</span>
                            )}
                          </span>
                          <InspectionStatus status={asset.inspection_status} />
                        </li>
                      ))}
                    </ul>
                  )}
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
