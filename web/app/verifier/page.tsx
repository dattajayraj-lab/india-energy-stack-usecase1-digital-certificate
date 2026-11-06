"use client";

import { useMutation } from "@tanstack/react-query";
import jsQR from "jsqr";
import { CheckCircle2Icon, InfoIcon, RefreshCwIcon, XCircleIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { CheckStatus } from "@/components/status";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError, type VerifyResult } from "@/lib/api";
import { fieldLabel } from "@/lib/field-labels";
import { useI18n, type MessageKey } from "@/lib/i18n";
import { formatValue } from "@/lib/sdjwt";

const SHARE_PATTERN = /#share=([\w-]+)/;

/** Flatten what was disclosed into label and value rows, leaving out structural ids. */
function disclosedRows(subject: Record<string, unknown>): { key: string; label: string; value: string }[] {
  const rows: { key: string; label: string; value: string }[] = [];
  const skip = new Set(["id", "type", "attributes", "parentResources", "meterId"]);
  const add = (object: Record<string, unknown>, prefix: string, group: string) => {
    for (const [key, value] of Object.entries(object)) {
      if (skip.has(key)) continue;
      const text = formatValue(value);
      if (text) rows.push({ key: `${prefix}.${key}`, label: `${group}${fieldLabel(key)}`, value: text });
    }
  };
  const profile = (subject.customerProfile ?? {}) as Record<string, unknown>;
  add((subject.customerDetails ?? {}) as Record<string, unknown>, "details", "");
  add(profile, "profile", "");
  ((profile.consumptionProfiles ?? []) as Record<string, unknown>[]).forEach((item, index) =>
    add(item, `consumption${index}`, ""),
  );
  ((profile.energyResources ?? []) as Record<string, unknown>[]).forEach((resource, index) => {
    const group = `${fieldLabel(String(resource.type))}: `;
    add((resource.attributes ?? {}) as Record<string, unknown>, `resource${index}`, group);
  });
  return rows.filter((row) => row.label !== "Energy Resources" && row.label !== "Consumption Profiles");
}

export default function VerifierPage() {
  const { t } = useI18n();
  const [text, setText] = useState("");
  const [challenge, setChallenge] = useState("");
  const [scanning, setScanning] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);

  const verify = useMutation({
    mutationFn: async (input: string) => {
      let credential = input.trim();
      const link = credential.match(SHARE_PATTERN);
      if (link) {
        try {
          const opened = await api<{ presentation: string }>("/shares/open", {
            method: "POST",
            body: { token: link[1] },
          });
          credential = opened.presentation;
        } catch (error) {
          if (error instanceof ApiError && error.status === 410) throw new Error(t("verify.linkGone"));
          throw error;
        }
      }
      return api<VerifyResult>("/verify", {
        method: "POST",
        body: { credential, expected_nonce: challenge.trim() || null },
      });
    },
    onError: (error) => toast.error(error.message),
  });
  const { mutate: runVerify } = verify;

  useEffect(() => {
    if (SHARE_PATTERN.test(window.location.hash)) runVerify(window.location.hash);
  }, [runVerify]);

  const readQr = useCallback(
    (source: CanvasImageSource, width: number, height: number): boolean => {
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext("2d");
      if (!context) return false;
      context.drawImage(source, 0, 0, width, height);
      const code = jsQR(context.getImageData(0, 0, width, height).data, width, height);
      if (!code) return false;
      setText(code.data);
      runVerify(code.data);
      return true;
    },
    [runVerify],
  );

  useEffect(() => {
    if (!scanning) return;
    let stream: MediaStream | undefined;
    let frame = 0;
    const tick = () => {
      const video = videoRef.current;
      if (video && video.readyState >= 2 && readQr(video, video.videoWidth, video.videoHeight)) {
        setScanning(false);
        return;
      }
      frame = requestAnimationFrame(tick);
    };
    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: "environment" } })
      .then((media) => {
        stream = media;
        if (videoRef.current) {
          videoRef.current.srcObject = media;
          void videoRef.current.play();
        }
        frame = requestAnimationFrame(tick);
      })
      .catch((error: Error) => {
        toast.error(error.message);
        setScanning(false);
      });
    return () => {
      cancelAnimationFrame(frame);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, [scanning, readQr]);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    const content = await file.text();
    setText(content);
    runVerify(content);
  };

  const onImage = async (file: File | undefined) => {
    if (!file) return;
    const bitmap = await createImageBitmap(file);
    if (!readQr(bitmap, bitmap.width, bitmap.height)) toast.error(t("verify.fail"));
  };

  const result = verify.data;
  const hasNotes = result?.checks.some((check) => check.status === "warn");
  const rows = result ? disclosedRows(result.disclosed) : [];

  return (
    <AppShell>
      <div className="grid gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("verify.title")}</h1>
          <p className="mt-1 text-muted-foreground">{t("verify.body")}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
          <Card>
            <CardContent>
              <Tabs defaultValue="paste">
                <TabsList>
                  <TabsTrigger value="paste">{t("verify.tab.paste")}</TabsTrigger>
                  <TabsTrigger value="upload">{t("verify.tab.upload")}</TabsTrigger>
                  <TabsTrigger value="scan">{t("verify.tab.scan")}</TabsTrigger>
                </TabsList>
                <TabsContent value="paste" className="mt-3 grid gap-3">
                  <Label htmlFor="credential">{t("verify.pasteLabel")}</Label>
                  <Textarea
                    id="credential"
                    rows={5}
                    className="max-h-48 font-mono text-xs break-all"
                    value={text}
                    onChange={(event) => setText(event.target.value)}
                  />
                  <Button disabled={!text.trim() || verify.isPending} onClick={() => runVerify(text)}>
                    {t("verify.check")}
                  </Button>
                </TabsContent>
                <TabsContent value="upload" className="mt-3 grid gap-3">
                  <Label htmlFor="file">{t("verify.uploadLabel")}</Label>
                  <Input
                    id="file"
                    type="file"
                    accept=".json,.txt,.jwt"
                    onChange={(event) => onFile(event.target.files?.[0])}
                  />
                </TabsContent>
                <TabsContent value="scan" className="mt-3 grid gap-3">
                  {scanning && (
                    // The camera preview has no audio or spoken content to caption.
                    // eslint-disable-next-line jsx-a11y/media-has-caption
                    <video ref={videoRef} playsInline muted className="w-full rounded-lg bg-muted" />
                  )}
                  <Button variant="outline" onClick={() => setScanning((value) => !value)}>
                    {scanning ? t("verify.scanStop") : t("verify.scanStart")}
                  </Button>
                  <Label htmlFor="qr-image">{t("verify.scanImage")}</Label>
                  <Input
                    id="qr-image"
                    type="file"
                    accept="image/*"
                    onChange={(event) => onImage(event.target.files?.[0])}
                  />
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t("verify.challenge.title")}</CardTitle>
              <CardDescription>{t("verify.challenge.body")}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Input
                aria-label={t("verify.challenge.title")}
                className="font-mono"
                value={challenge}
                onChange={(event) => setChallenge(event.target.value)}
              />
              <Button variant="outline" onClick={() => setChallenge(crypto.randomUUID().slice(0, 8))}>
                <RefreshCwIcon className="size-4" aria-hidden />
                {t("verify.challenge.new")}
              </Button>
            </CardContent>
          </Card>
        </div>

        {result && (
          <div className="grid gap-4" aria-live="polite">
            <Alert variant={result.valid ? "default" : "destructive"} data-testid="verify-result">
              {result.valid ? (
                hasNotes ? (
                  <InfoIcon aria-hidden />
                ) : (
                  <CheckCircle2Icon aria-hidden />
                )
              ) : (
                <XCircleIcon aria-hidden />
              )}
              <AlertTitle>
                {result.valid ? (hasNotes ? t("verify.passNotes") : t("verify.pass")) : t("verify.fail")}
              </AlertTitle>
              <AlertDescription>
                {result.valid ? t("verify.passBody") : t("verify.failBody")}
                {result.issuer && (
                  <span className="block font-mono text-xs break-all">
                    {t("verify.issuer")}: {result.issuer}
                  </span>
                )}
              </AlertDescription>
            </Alert>
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>{t("verify.disclosed")}</CardTitle>
                </CardHeader>
                <CardContent>
                  {rows.length === 0 ? (
                    <p className="text-sm text-muted-foreground">{t("verify.nothing")}</p>
                  ) : (
                    <dl className="divide-y" data-testid="disclosed">
                      {rows.map((row) => (
                        <div key={row.key} className="flex justify-between gap-4 py-1.5 text-sm">
                          <dt className="text-muted-foreground">{row.label}</dt>
                          <dd className="text-right font-medium break-words">{row.value}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>{t("verify.checks")}</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="divide-y">
                    {result.checks.map((check) => (
                      <li key={check.id} className="grid gap-1 py-2" data-check={check.id} data-status={check.status}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium">{t(`check.${check.id}` as MessageKey)}</span>
                          <CheckStatus status={check.status} />
                        </div>
                        <p className="text-xs break-words text-muted-foreground">{check.detail}</p>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
