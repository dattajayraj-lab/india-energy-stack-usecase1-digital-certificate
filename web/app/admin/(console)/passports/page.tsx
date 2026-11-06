"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Pager } from "@/components/pager";
import { PassportStatus } from "@/components/status";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, type Page, type Passport } from "@/lib/api";
import { formatDate, useI18n, type MessageKey } from "@/lib/i18n";

const PAGE_SIZE = 20;

export default function Passports() {
  const { t, locale } = useI18n();
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);

  const { data } = useQuery({
    queryKey: ["admin-passports", status, page],
    queryFn: () => {
      const filter = status === "all" ? "" : `&status=${status}`;
      return api<Page<Passport>>(`/admin/passports?page=${page}&page_size=${PAGE_SIZE}${filter}`, { portal: "admin" });
    },
  });

  return (
    <Card>
      <CardContent className="grid gap-3">
        <Tabs
          value={status}
          onValueChange={(value) => {
            setStatus(String(value));
            setPage(1);
          }}
        >
          <TabsList>
            <TabsTrigger value="all">{t("admin.filter.all")}</TabsTrigger>
            <TabsTrigger value="active">{t("status.active")}</TabsTrigger>
            <TabsTrigger value="revoked">{t("status.revoked")}</TabsTrigger>
          </TabsList>
        </Tabs>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("admin.col.consumer")}</TableHead>
              <TableHead>{t("admin.col.version")}</TableHead>
              <TableHead>{t("admin.col.binding")}</TableHead>
              <TableHead>{t("admin.col.issued")}</TableHead>
              <TableHead>{t("wallet.validUntil")}</TableHead>
              <TableHead>{t("admin.col.status")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data?.items.map((passport) => (
              <TableRow key={passport.id}>
                <TableCell className="font-mono">{passport.consumer_no}</TableCell>
                <TableCell>{passport.version}</TableCell>
                <TableCell>{t(`binding.${passport.binding}` as MessageKey)}</TableCell>
                <TableCell>{formatDate(passport.issued_at, locale)}</TableCell>
                <TableCell>{formatDate(passport.expires_at, locale)}</TableCell>
                <TableCell>
                  <PassportStatus status={passport.status} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {data && <Pager page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />}
      </CardContent>
    </Card>
  );
}
