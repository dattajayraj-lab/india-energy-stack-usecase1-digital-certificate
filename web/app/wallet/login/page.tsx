"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import { api, setSession } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const schema = z.object({ consumer_no: z.string().regex(/^\d{4,32}$/, "Enter the digits of your consumer number") });

export default function WalletLogin() {
  const { t } = useI18n();
  const router = useRouter();
  const [consumerNo, setConsumerNo] = useState<string | null>(null);
  const [devCode, setDevCode] = useState<string | null>(null);
  const [otp, setOtp] = useState("");
  const form = useForm<z.infer<typeof schema>>({ resolver: zodResolver(schema), defaultValues: { consumer_no: "" } });

  const request = useMutation({
    mutationFn: (values: z.infer<typeof schema>) =>
      api<{ dev_otp?: string }>("/auth/otp/request", { method: "POST", body: values }),
    onSuccess: (data, values) => {
      setConsumerNo(values.consumer_no);
      setDevCode(data.dev_otp ?? null);
    },
    onError: (error) => toast.error(error.message),
  });

  const verify = useMutation({
    mutationFn: () =>
      api<{ access_token: string; role: string }>("/auth/otp/verify", {
        method: "POST",
        body: { consumer_no: consumerNo, otp },
      }),
    onSuccess: (data) => {
      setSession("consumer", { token: data.access_token, role: data.role, subject: consumerNo ?? "" });
      router.replace("/wallet");
    },
    onError: (error) => {
      setOtp("");
      toast.error(error.message);
    },
  });

  return (
    <AppShell>
      <Card className="mx-auto max-w-md">
        <CardHeader>
          <CardTitle>{t("login.consumer.title")}</CardTitle>
          <CardDescription>{t("login.consumer.body")}</CardDescription>
        </CardHeader>
        <CardContent>
          {consumerNo === null ? (
            <form className="grid gap-4" onSubmit={form.handleSubmit((values) => request.mutate(values))}>
              <div className="grid gap-2">
                <Label htmlFor="consumer_no">{t("login.consumerNo")}</Label>
                <Input
                  id="consumer_no"
                  inputMode="numeric"
                  autoComplete="off"
                  aria-invalid={!!form.formState.errors.consumer_no}
                  {...form.register("consumer_no")}
                />
                {form.formState.errors.consumer_no && (
                  <p className="text-sm text-destructive">{form.formState.errors.consumer_no.message}</p>
                )}
              </div>
              <Button type="submit" disabled={request.isPending}>
                {t("login.sendCode")}
              </Button>
            </form>
          ) : (
            <form
              className="grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                verify.mutate();
              }}
            >
              <div className="grid gap-2">
                <Label htmlFor="otp">{t("login.enterCode")}</Label>
                <InputOTP id="otp" maxLength={6} value={otp} onChange={setOtp} inputMode="numeric">
                  <InputOTPGroup>
                    {[0, 1, 2, 3, 4, 5].map((index) => (
                      <InputOTPSlot key={index} index={index} />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
                {devCode && (
                  <p className="text-sm text-muted-foreground" data-testid="dev-otp">
                    {t("login.devCode")}: {devCode}
                  </p>
                )}
              </div>
              <Button type="submit" disabled={otp.length !== 6 || verify.isPending}>
                {t("login.verify")}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setConsumerNo(null)}>
                {t("login.changeNumber")}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </AppShell>
  );
}
