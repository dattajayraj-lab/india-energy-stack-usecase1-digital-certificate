"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { InspectionStatus, PassportStatus, StateBadge } from "@/components/status";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, ApiError, getSession, type ConsumerSummary, type IssueResult, type Preview } from "@/lib/api";
import { fieldLabel } from "@/lib/field-labels";
import { useI18n, type MessageKey } from "@/lib/i18n";
import { formatValue } from "@/lib/sdjwt";

const REASONS = ["meter_swap", "load_change", "der_change", "request"] as const;
type Reason = (typeof REASONS)[number];

function PreviewPanel({ consumerNo }: { consumerNo: string }) {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const role = getSession("admin")?.role;
  const canIssue = role === "admin" || role === "operator";
  const [consent, setConsent] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  const [reason, setReason] = useState<Reason>("request");

  const preview = useQuery({
    queryKey: ["preview", consumerNo],
    queryFn: () => api<Preview>(`/admin/consumers/${consumerNo}/preview`, { portal: "admin" }),
  });
  const refresh = () => queryClient.invalidateQueries();
  const fail = (error: Error) => {
    const flags = error instanceof ApiError && error.flags.length ? `: ${error.flags.map((f) => f.code).join(", ")}` : "";
    toast.error(`${error.message}${flags}`);
  };

  const issue = useMutation({
    mutationFn: () =>
      api<IssueResult>("/passports/issue", {
        method: "POST",
        portal: "admin",
        body: { consumer_no: consumerNo, consent: true },
      }),
    onSuccess: () => {
      toast.success(t("admin.issue.done"));
      setIssueOpen(false);
      setConsent(false);
      refresh();
    },
    onError: fail,
  });
  const active = preview.data?.active_passport;
  const revoke = useMutation({
    mutationFn: () =>
      api(`/passports/${active?.id}/revoke`, { method: "POST", portal: "admin", body: { reason } }),
    onSuccess: () => {
      toast.success(t("admin.revoke.done"));
      refresh();
    },
    onError: fail,
  });
  const reissue = useMutation({
    mutationFn: () =>
      api<IssueResult>(`/passports/${active?.id}/reissue`, { method: "POST", portal: "admin", body: { reason } }),
    onSuccess: () => {
      toast.success(t("admin.issue.done"));
      refresh();
    },
    onError: fail,
  });

  const data = preview.data;
  if (!data) return null;
  const consumption = data.subject.customerProfile.consumptionProfiles[0] ?? {};
  const reasonItems = REASONS.map((value) => ({ value, label: t(`reason.${value}` as MessageKey) }));
  const reasonPicker = (
    <div className="grid gap-2">
      <Label>{t("admin.revoke.reason")}</Label>
      <Select items={reasonItems} value={reason} onValueChange={(value) => setReason(value as Reason)}>
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {reasonItems.map((item) => (
            <SelectItem key={item.value} value={item.value}>
              {item.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );

  return (
    <Card data-testid="preview">
      <CardHeader>
        <CardTitle>{t("admin.preview")}</CardTitle>
        <CardDescription>
          {String(data.subject.customerDetails.fullName ?? "")} · {consumerNo}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {data.flags.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("admin.preview.clean")}</p>
        ) : (
          <ul className="grid gap-2">
            {data.flags.map((flag, index) => (
              <li key={`${flag.code}-${index}`} className="grid gap-1 text-sm" data-flag={flag.code}>
                <StateBadge tone={flag.severity === "blocker" ? "bad" : "warn"}>
                  {t(flag.severity === "blocker" ? "admin.blocker" : "admin.warning")}
                </StateBadge>
                <span>{flag.message}</span>
              </li>
            ))}
          </ul>
        )}
        <dl className="grid gap-x-6 sm:grid-cols-2">
          {Object.entries(consumption)
            .filter(([key]) => key !== "meterId")
            .map(([key, value]) => (
              <div key={key} className="flex justify-between gap-4 border-b py-1.5 text-sm">
                <dt className="text-muted-foreground">{fieldLabel(key)}</dt>
                <dd className="font-medium">{formatValue(value)}</dd>
              </div>
            ))}
        </dl>
        <ul className="divide-y">
          {data.subject.customerProfile.energyResources.map((resource) => {
            const attributes = resource.attributes ?? {};
            const inspection = attributes.inspection as { result?: string } | undefined;
            return (
              <li key={resource.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                <span>
                  <span className="font-medium">{fieldLabel(resource.type)}</span>
                  <span className="text-muted-foreground"> · {String(attributes.serialNumber ?? resource.id.split(":").pop())}</span>
                  {!!attributes.maxExport && (
                    <span className="text-muted-foreground"> · {formatValue(attributes.maxExport)}</span>
                  )}
                </span>
                {resource.type !== "METER" && <InspectionStatus status={inspection?.result ?? "none"} />}
              </li>
            );
          })}
        </ul>
      </CardContent>
      {canIssue && (
        <CardFooter className="flex flex-wrap gap-2">
          {!active ? (
            <Dialog open={issueOpen} onOpenChange={setIssueOpen}>
              <DialogTrigger render={<Button disabled={!data.issuable} />}>{t("admin.issue")}</DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{t("admin.issue")}</DialogTitle>
                  <DialogDescription>{t("admin.issue.note")}</DialogDescription>
                </DialogHeader>
                <div className="flex items-start gap-2">
                  <Checkbox
                    id="issue-consent"
                    checked={consent}
                    onCheckedChange={(value) => setConsent(value === true)}
                  />
                  <Label htmlFor="issue-consent" className="leading-snug font-normal">
                    {t("admin.issue.confirm")}
                  </Label>
                </div>
                <DialogFooter>
                  <Button disabled={!consent || issue.isPending} onClick={() => issue.mutate()}>
                    {t("admin.issue")}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          ) : (
            <>
              <AlertDialog>
                <AlertDialogTrigger render={<Button variant="outline" />}>{t("admin.reissue")}</AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>{t("admin.reissue.title")}</AlertDialogTitle>
                    <AlertDialogDescription>{t("admin.reissue.body")}</AlertDialogDescription>
                  </AlertDialogHeader>
                  {reasonPicker}
                  <AlertDialogFooter>
                    <AlertDialogCancel>{t("admin.cancel")}</AlertDialogCancel>
                    <AlertDialogAction onClick={() => reissue.mutate()}>{t("admin.reissue")}</AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
              {role === "admin" && (
                <AlertDialog>
                  <AlertDialogTrigger render={<Button variant="destructive" />}>{t("admin.revoke")}</AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{t("admin.revoke.title")}</AlertDialogTitle>
                      <AlertDialogDescription>{t("admin.revoke.body")}</AlertDialogDescription>
                    </AlertDialogHeader>
                    {reasonPicker}
                    <AlertDialogFooter>
                      <AlertDialogCancel>{t("admin.cancel")}</AlertDialogCancel>
                      <AlertDialogAction onClick={() => revoke.mutate()}>{t("admin.revoke")}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
            </>
          )}
        </CardFooter>
      )}
    </Card>
  );
}

export default function Consumers() {
  const { t } = useI18n();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query), 200);
    return () => clearTimeout(timer);
  }, [query]);

  const consumers = useQuery({
    queryKey: ["consumers", debounced],
    queryFn: () =>
      api<ConsumerSummary[]>(`/admin/consumers?q=${encodeURIComponent(debounced)}`, { portal: "admin" }),
  });

  return (
    <div className="grid gap-4">
      <Card>
        <CardContent className="grid gap-3">
          <Command shouldFilter={false} className="rounded-lg border">
            <CommandInput placeholder={t("admin.search")} value={query} onValueChange={setQuery} />
            {query && (
              <CommandList>
                <CommandEmpty>{t("admin.noResults")}</CommandEmpty>
                {consumers.data?.map((consumer) => (
                  <CommandItem
                    key={consumer.consumer_no}
                    value={consumer.consumer_no}
                    onSelect={() => setSelected(consumer.consumer_no)}
                  >
                    {consumer.name} · {consumer.consumer_no}
                  </CommandItem>
                ))}
              </CommandList>
            )}
          </Command>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("admin.col.consumer")}</TableHead>
                <TableHead>{t("admin.col.name")}</TableHead>
                <TableHead>{t("admin.col.connection")}</TableHead>
                <TableHead>{t("admin.col.tariff")}</TableHead>
                <TableHead>{t("admin.col.passport")}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {consumers.data?.map((consumer) => (
                <TableRow key={consumer.consumer_no}>
                  <TableCell className="font-mono">{consumer.consumer_no}</TableCell>
                  <TableCell>{consumer.name}</TableCell>
                  <TableCell>{consumer.service_conn_no}</TableCell>
                  <TableCell>{consumer.tariff_category}</TableCell>
                  <TableCell>
                    <PassportStatus status={consumer.passport_status} />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`${t("admin.review")} ${consumer.consumer_no}`}
                      onClick={() => setSelected(consumer.consumer_no)}
                    >
                      {t("admin.review")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      {selected && <PreviewPanel key={selected} consumerNo={selected} />}
    </div>
  );
}
