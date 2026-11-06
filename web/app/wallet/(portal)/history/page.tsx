"use client";

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { StateBadge } from "@/components/status";
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, type Passport, type Share } from "@/lib/api";
import { fieldLabel } from "@/lib/field-labels";
import { formatDate, useI18n } from "@/lib/i18n";

function shortFields(paths: string[]): string {
  const leaves = paths.filter((path) => !paths.some((other) => other.startsWith(`${path}.`)));
  return leaves.map((path) => fieldLabel(path.split(".").pop() ?? path)).join(", ");
}

export default function ShareHistory() {
  const { t, locale } = useI18n();
  const queryClient = useQueryClient();
  const passports = useQuery({
    queryKey: ["mine"],
    queryFn: () => api<Passport[]>("/passports/mine", { portal: "consumer" }),
  });
  const results = useQueries({
    queries: (passports.data ?? []).map((passport) => ({
      queryKey: ["shares", passport.id],
      queryFn: () => api<Share[]>(`/passports/${passport.id}/shares`, { portal: "consumer" }),
    })),
  });
  const shares = results.flatMap((result) => result.data ?? []).sort((a, b) => b.id - a.id);

  const withdraw = useMutation({
    mutationFn: (id: number) => api(`/shares/${id}`, { method: "DELETE", portal: "consumer" }),
    onSuccess: () => {
      toast.success(t("history.withdrawn"));
      queryClient.invalidateQueries({ queryKey: ["shares"] });
    },
    onError: (error) => toast.error(error.message),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("history.title")}</CardTitle>
      </CardHeader>
      <CardContent>
        {shares.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("history.empty")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("history.to")}</TableHead>
                <TableHead>{t("history.fields")}</TableHead>
                <TableHead>{t("history.expires")}</TableHead>
                <TableHead>{t("history.opened")}</TableHead>
                <TableHead>{t("field.status")}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shares.map((share) => {
                const expired = new Date(share.expires_at).getTime() < Date.now();
                const live = !share.revoked_at && !expired;
                return (
                  <TableRow key={share.id}>
                    <TableCell>{share.verifier_hint ?? t("history.unnamed")}</TableCell>
                    <TableCell className="max-w-56 whitespace-normal">{shortFields(share.disclosed_fields)}</TableCell>
                    <TableCell>{formatDate(share.expires_at, locale)}</TableCell>
                    <TableCell>{share.used_count}</TableCell>
                    <TableCell>
                      {share.revoked_at ? (
                        <StateBadge tone="muted">{t("history.withdrawn")}</StateBadge>
                      ) : expired ? (
                        <StateBadge tone="muted">{t("history.expired")}</StateBadge>
                      ) : (
                        <StateBadge tone="good">{t("history.live")}</StateBadge>
                      )}
                    </TableCell>
                    <TableCell>
                      {live && (
                        <AlertDialog>
                          <AlertDialogTrigger render={<Button variant="outline" size="sm" />}>
                            {t("history.withdraw")}
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>{t("history.confirm.title")}</AlertDialogTitle>
                              <AlertDialogDescription>{t("history.confirm.body")}</AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>{t("admin.cancel")}</AlertDialogCancel>
                              <AlertDialogAction onClick={() => withdraw.mutate(share.id)}>
                                {t("history.withdraw")}
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
