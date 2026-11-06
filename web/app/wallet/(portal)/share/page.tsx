"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { CopyIcon } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { api, getSession, type Passport } from "@/lib/api";
import { fieldLabel } from "@/lib/field-labels";
import { useI18n, type MessageKey } from "@/lib/i18n";
import {
  fieldGroup,
  formatValue,
  parseCredential,
  presetPaths,
  selectedLeaves,
  withAncestors,
  withoutDescendants,
  type FieldGroup,
  type FieldNode,
  type PresetName,
} from "@/lib/sdjwt";
import { buildPresentation, loadCredential } from "@/lib/wallet";

const PRESETS: PresetName[] = ["lender", "marketplace", "subsidy"];
const GROUPS: FieldGroup[] = ["connection", "assets", "personal"];
const EXPIRY_SECONDS = { "1h": 3600, "1d": 86400, "7d": 604800 } as const;
type Expiry = keyof typeof EXPIRY_SECONDS;

function FieldRow({
  node,
  selected,
  onToggle,
}: {
  node: FieldNode;
  selected: Set<string>;
  onToggle: (node: FieldNode, checked: boolean) => void;
}) {
  const id = `field-${node.path}`;
  const value = node.children.length === 0 ? formatValue(node.value) : "";
  return (
    <li>
      <div className="flex items-start gap-2 py-1.5">
        <Checkbox
          id={id}
          data-field={node.path}
          checked={selected.has(node.path)}
          onCheckedChange={(checked) => onToggle(node, checked === true)}
        />
        <Label htmlFor={id} className="grid min-w-0 gap-0.5 font-normal">
          <span className="font-medium">{fieldLabel(node.name)}</span>
          {value && <span className="text-sm break-all text-muted-foreground">{value}</span>}
        </Label>
      </div>
      {/* An item's details stay folded until the item itself is chosen. */}
      {node.children.length > 0 && selected.has(node.path) && (
        <ul className="ml-3 border-l pl-3">
          {node.children.map((child) => (
            <FieldRow key={child.path} node={child} selected={selected} onToggle={onToggle} />
          ))}
        </ul>
      )}
    </li>
  );
}

interface Created {
  url: string;
  presentation: string;
}

export default function SharePage() {
  const { t } = useI18n();
  const consumerNo = getSession("consumer")?.subject ?? "";
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirming, setConfirming] = useState(false);
  const [created, setCreated] = useState<Created | null>(null);
  const [consent, setConsent] = useState(false);
  const [hint, setHint] = useState("");
  const [challenge, setChallenge] = useState("");
  const [expiry, setExpiry] = useState<Expiry>("1d");

  const passports = useQuery({
    queryKey: ["mine"],
    queryFn: () => api<Passport[]>("/passports/mine", { portal: "consumer" }),
  });
  const current = passports.data?.find((p) => p.status === "active");

  const credential = useQuery({
    queryKey: ["credential-tree", consumerNo, current?.credential_id],
    enabled: !!current,
    queryFn: async () => {
      const stored = await loadCredential(consumerNo);
      if (!stored || stored.credentialId !== current?.credential_id) return null;
      return parseCredential(stored.token);
    },
  });
  const parsed = credential.data;

  const chosen = useMemo(
    () => parsed?.nodes.filter((node) => selected.has(node.path)) ?? [],
    [parsed, selected],
  );

  const toggle = (node: FieldNode, checked: boolean) => {
    if (!parsed) return;
    setSelected((previous) => {
      if (!checked) return withoutDescendants(previous, node);
      return withAncestors(new Set(previous).add(node.path), parsed.nodes);
    });
  };

  const share = useMutation({
    mutationFn: async () => {
      if (!parsed || !current) throw new Error(t("share.needPassport"));
      const presentation = await buildPresentation(
        parsed.issuerJwt,
        chosen.map((node) => node.raw),
        challenge.trim() || crypto.randomUUID(),
        hint.trim() || "any-verifier",
      );
      const result = await api<{ url: string }>(`/passports/${current.id}/share`, {
        method: "POST",
        portal: "consumer",
        body: {
          presentation,
          disclosed_fields: chosen.map((node) => node.path),
          ttl_seconds: EXPIRY_SECONDS[expiry],
          verifier_hint: hint.trim() || null,
          consent,
        },
      });
      return { url: result.url, presentation };
    },
    onSuccess: (result) => {
      setCreated(result);
      setConfirming(false);
      setConsent(false);
    },
    onError: (error) => toast.error(error.message),
  });

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    toast.success(t("share.copied"));
  };

  if (passports.isLoading || credential.isLoading) return <Skeleton className="h-64 w-full" />;
  if (!parsed) {
    return (
      <Alert>
        <AlertDescription>{t("share.needPassport")}</AlertDescription>
      </Alert>
    );
  }

  const leaves = selectedLeaves(chosen, selected);
  const expiryItems = (Object.keys(EXPIRY_SECONDS) as Expiry[]).map((value) => ({
    value,
    label: t(`share.expiry.${value}` as MessageKey),
  }));

  return (
    <div className="grid gap-4 pb-24">
      <Card>
        <CardHeader>
          <CardTitle>{t("share.title")}</CardTitle>
          <CardDescription>{t("share.body")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-2">
            <span className="text-sm font-medium">{t("share.presets")}</span>
            <div className="flex flex-wrap gap-2">
              {PRESETS.map((preset) => (
                <Button
                  key={preset}
                  variant="outline"
                  size="sm"
                  onClick={() => setSelected(presetPaths(preset, parsed.nodes))}
                >
                  {t(`preset.${preset}` as MessageKey)}
                </Button>
              ))}
            </div>
          </div>
          {GROUPS.map((group) => (
            <section key={group} className="grid gap-1">
              <h2 className="text-sm font-semibold">{t(`share.group.${group}` as MessageKey)}</h2>
              <ul>
                {parsed.roots
                  .filter((node) => fieldGroup(node) === group)
                  .map((node) => (
                    <FieldRow key={node.path} node={node} selected={selected} onToggle={toggle} />
                  ))}
              </ul>
            </section>
          ))}
        </CardContent>
      </Card>

      <div className="fixed inset-x-0 bottom-0 z-10 border-t bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-3 px-4 py-3">
          <span className="text-sm text-muted-foreground" data-testid="selected-count">
            {leaves.length} {t("share.selected")}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={() => setSelected(new Set())}>
              {t("share.clear")}
            </Button>
            <Button disabled={chosen.length === 0} onClick={() => setConfirming(true)}>
              {t("share.continue")}
            </Button>
          </div>
        </div>
      </div>

      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("share.dialog.title")}</DialogTitle>
            <DialogDescription>
              {leaves.map((node) => fieldLabel(node.name)).join(", ")}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="hint">{t("share.verifierName")}</Label>
              <Input id="hint" maxLength={128} value={hint} onChange={(e) => setHint(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="challenge">{t("share.challenge")}</Label>
              <Input id="challenge" value={challenge} onChange={(e) => setChallenge(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label>{t("share.expiry")}</Label>
              <Select items={expiryItems} value={expiry} onValueChange={(value) => setExpiry(value as Expiry)}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {expiryItems.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-start gap-2">
              <Switch id="share-consent" checked={consent} onCheckedChange={setConsent} />
              <Label htmlFor="share-consent" className="leading-snug font-normal">
                {t("share.consent")}
              </Label>
            </div>
          </div>
          <DialogFooter>
            <Button disabled={!consent || share.isPending} onClick={() => share.mutate()}>
              {t("share.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={created !== null} onOpenChange={(open) => !open && setCreated(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("share.ready")}</DialogTitle>
            <DialogDescription>{t("share.readyBody")}</DialogDescription>
          </DialogHeader>
          {created && (
            <div className="grid gap-3">
              <div className="mx-auto rounded-lg bg-white p-3">
                <QRCodeSVG value={created.url} size={200} title={t("share.ready")} />
              </div>
              <Input readOnly value={created.url} aria-label={t("share.copyLink")} data-testid="share-url" />
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" onClick={() => copy(created.url)}>
                  <CopyIcon className="size-4" aria-hidden />
                  {t("share.copyLink")}
                </Button>
                <Button variant="outline" onClick={() => copy(created.presentation)}>
                  <CopyIcon className="size-4" aria-hidden />
                  {t("share.copyRaw")}
                </Button>
              </div>
              <p className="text-sm text-muted-foreground">{t("share.rawHint")}</p>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setCreated(null)}>{t("share.done")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
