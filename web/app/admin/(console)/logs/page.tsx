"use client";

import { useQuery } from "@tanstack/react-query";
import { CalendarIcon } from "lucide-react";
import { useState } from "react";
import { Pager } from "@/components/pager";
import { StateBadge } from "@/components/status";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, ApiError, type AuditRow, type Page, type VerificationRow } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const PAGE_SIZE = 20;

const isoDay = (date: Date) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
const stamp = (value: string) => new Date(value).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" });

function DatePicker({ label, value, onChange }: { label: string; value?: Date; onChange: (date?: Date) => void }) {
  return (
    <Popover>
      <PopoverTrigger render={<Button variant="outline" size="sm" />}>
        <CalendarIcon className="size-4" aria-hidden />
        {value ? isoDay(value) : label}
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0">
        <Calendar mode="single" selected={value} onSelect={onChange} />
      </PopoverContent>
    </Popover>
  );
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") search.set(key, String(value));
  });
  return search.toString();
}

export default function Logs() {
  const { t } = useI18n();
  const [from, setFrom] = useState<Date>();
  const [to, setTo] = useState<Date>();
  const [action, setAction] = useState("");
  const [auditPage, setAuditPage] = useState(1);
  const [verifyPage, setVerifyPage] = useState(1);
  const range = { date_from: from && isoDay(from), date_to: to && isoDay(to) };

  const audit = useQuery({
    queryKey: ["audit", action, range, auditPage],
    queryFn: () =>
      api<Page<AuditRow>>(`/admin/audit?${query({ ...range, action, page: auditPage, page_size: PAGE_SIZE })}`, {
        portal: "admin",
      }),
  });
  const verifications = useQuery({
    queryKey: ["verifications", range, verifyPage],
    queryFn: () =>
      api<Page<VerificationRow>>(`/admin/verifications?${query({ ...range, page: verifyPage, page_size: PAGE_SIZE })}`, {
        portal: "admin",
      }),
  });

  if (audit.error instanceof ApiError && audit.error.status === 403) {
    return (
      <Alert>
        <AlertDescription>{t("logs.forbidden")}</AlertDescription>
      </Alert>
    );
  }

  return (
    <Card>
      <CardContent className="grid gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <DatePicker label={t("logs.from")} value={from} onChange={setFrom} />
          <DatePicker label={t("logs.to")} value={to} onChange={setTo} />
          <Input
            className="max-w-48"
            placeholder={t("logs.action")}
            aria-label={t("logs.action")}
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setAuditPage(1);
            }}
          />
        </div>
        <Tabs defaultValue="audit">
          <TabsList>
            <TabsTrigger value="audit">{t("logs.audit")}</TabsTrigger>
            <TabsTrigger value="verifications">{t("logs.verifications")}</TabsTrigger>
          </TabsList>
          <TabsContent value="audit" className="mt-3 grid gap-3">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("logs.time")}</TableHead>
                  <TableHead>{t("logs.actor")}</TableHead>
                  <TableHead>{t("logs.action")}</TableHead>
                  <TableHead>{t("logs.entity")}</TableHead>
                  <TableHead>{t("logs.ip")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.data?.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>{stamp(row.at)}</TableCell>
                    <TableCell>{row.actor}</TableCell>
                    <TableCell className="font-mono text-xs">{row.action}</TableCell>
                    <TableCell>
                      {row.entity} {row.entity_id}
                    </TableCell>
                    <TableCell>{row.ip ?? ""}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {audit.data?.total === 0 && <p className="text-sm text-muted-foreground">{t("logs.empty")}</p>}
            {audit.data && (
              <Pager page={auditPage} pageSize={PAGE_SIZE} total={audit.data.total} onPage={setAuditPage} />
            )}
          </TabsContent>
          <TabsContent value="verifications" className="mt-3 grid gap-3">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("logs.time")}</TableHead>
                  <TableHead>{t("logs.credential")}</TableHead>
                  <TableHead>{t("logs.result")}</TableHead>
                  <TableHead>{t("logs.failed")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {verifications.data?.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>{stamp(row.checked_at)}</TableCell>
                    <TableCell className="max-w-48 truncate font-mono text-xs">{row.credential_id ?? ""}</TableCell>
                    <TableCell>
                      <StateBadge tone={row.result === "pass" ? "good" : "bad"}>
                        {t(row.result === "pass" ? "logs.pass" : "logs.fail")}
                      </StateBadge>
                    </TableCell>
                    <TableCell>{row.failed_checks.join(", ")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {verifications.data?.total === 0 && <p className="text-sm text-muted-foreground">{t("logs.empty")}</p>}
            {verifications.data && (
              <Pager page={verifyPage} pageSize={PAGE_SIZE} total={verifications.data.total} onPage={setVerifyPage} />
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
