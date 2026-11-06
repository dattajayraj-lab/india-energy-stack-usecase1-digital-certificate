"use client";

import { useQuery } from "@tanstack/react-query";
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, type Dashboard } from "@/lib/api";
import { useI18n, type MessageKey } from "@/lib/i18n";

function Stat({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-3xl tabular-nums">{value}</CardTitle>
        {note && <p className="text-xs text-muted-foreground">{note}</p>}
      </CardHeader>
    </Card>
  );
}

const shortDay = (day: string) =>
  new Date(`${day}T00:00:00`).toLocaleDateString("en-IN", { day: "numeric", month: "short" });

export default function AdminDashboard() {
  const { t } = useI18n();
  const { data } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<Dashboard>("/admin/dashboard", { portal: "admin" }),
  });
  if (!data) return <Skeleton className="h-96 w-full" />;

  const config = {
    issued: { label: t("admin.dash.seriesIssued"), color: "var(--chart-1)" },
    verified: { label: t("admin.dash.seriesVerified"), color: "var(--chart-2)" },
  } satisfies ChartConfig;

  const reasons = Object.entries(data.revocations_by_reason);

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label={t("admin.dash.issued")} value={data.issued} />
        <Stat label={t("admin.dash.active")} value={data.active} />
        <Stat
          label={t("admin.dash.revoked")}
          value={data.revoked}
          note={data.pending_reissue ? `${data.pending_reissue} ${t("admin.dash.pending")}` : undefined}
        />
        <Stat
          label={t("admin.dash.verified")}
          value={data.verified_pass}
          note={`${data.verified_fail} ${t("admin.dash.failed")}`}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin.dash.trend")}</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="chart">
            <TabsList>
              <TabsTrigger value="chart">{t("admin.dash.chart")}</TabsTrigger>
              <TabsTrigger value="table">{t("admin.dash.table")}</TabsTrigger>
            </TabsList>
            <TabsContent value="chart" className="mt-3">
              <ChartContainer config={config} className="h-64 w-full">
                <LineChart data={data.by_day} margin={{ left: 0, right: 12, top: 8 }}>
                  <CartesianGrid vertical={false} strokeWidth={1} />
                  <XAxis dataKey="day" tickLine={false} axisLine={false} tickFormatter={shortDay} minTickGap={32} />
                  <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={28} />
                  <ChartTooltip content={<ChartTooltipContent labelFormatter={(day) => shortDay(String(day))} />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  {(["issued", "verified"] as const).map((series) => (
                    <Line
                      key={series}
                      dataKey={series}
                      type="linear"
                      stroke={`var(--color-${series})`}
                      strokeWidth={2}
                      strokeLinecap="round"
                      dot={false}
                      activeDot={{ r: 4, stroke: "var(--card)", strokeWidth: 2 }}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              </ChartContainer>
            </TabsContent>
            <TabsContent value="table" className="mt-3">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("admin.dash.day")}</TableHead>
                    <TableHead className="text-right">{t("admin.dash.seriesIssued")}</TableHead>
                    <TableHead className="text-right">{t("admin.dash.seriesVerified")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.by_day.map((row) => (
                    <TableRow key={row.day}>
                      <TableCell>{shortDay(row.day)}</TableCell>
                      <TableCell className="text-right tabular-nums">{row.issued}</TableCell>
                      <TableCell className="text-right tabular-nums">{row.verified}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin.dash.reasons")}</CardTitle>
        </CardHeader>
        <CardContent>
          {reasons.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("admin.dash.noReasons")}</p>
          ) : (
            <dl className="divide-y">
              {reasons.map(([reason, count]) => (
                <div key={reason} className="flex justify-between py-1.5 text-sm">
                  <dt className="text-muted-foreground">{t(`reason.${reason}` as MessageKey)}</dt>
                  <dd className="font-medium tabular-nums">{count}</dd>
                </div>
              ))}
            </dl>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
