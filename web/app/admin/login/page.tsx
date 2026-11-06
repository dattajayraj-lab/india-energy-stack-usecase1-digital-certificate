"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, setSession } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const schema = z.object({ username: z.string().min(1), password: z.string().min(1) });
type Values = z.infer<typeof schema>;

export default function AdminLogin() {
  const { t } = useI18n();
  const router = useRouter();
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { username: "", password: "" } });

  const login = useMutation({
    mutationFn: (values: Values) =>
      api<{ access_token: string; role: string }>("/auth/admin/login", { method: "POST", body: values }),
    onSuccess: (data, values) => {
      setSession("admin", { token: data.access_token, role: data.role, subject: values.username });
      router.replace("/admin");
    },
    onError: (error) => toast.error(error.message),
  });

  return (
    <AppShell>
      <Card className="mx-auto max-w-md">
        <CardHeader>
          <CardTitle>{t("login.admin.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4" onSubmit={form.handleSubmit((values) => login.mutate(values))}>
            <div className="grid gap-2">
              <Label htmlFor="username">{t("login.username")}</Label>
              <Input id="username" autoComplete="username" {...form.register("username")} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password">{t("login.password")}</Label>
              <Input id="password" type="password" autoComplete="current-password" {...form.register("password")} />
            </div>
            <Button type="submit" disabled={login.isPending}>
              {t("login.signIn")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AppShell>
  );
}
