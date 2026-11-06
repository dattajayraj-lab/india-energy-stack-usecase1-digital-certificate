/** Reads an SD-JWT into a tree of fields the consumer can tick. Paths match the API's. */

import { fieldRank } from "@/lib/field-labels";
import { sha256B64u } from "@/lib/wallet";

export interface FieldNode {
  path: string;
  name: string;
  value: unknown;
  raw: string;
  parent: FieldNode | null;
  children: FieldNode[];
}

export interface ParsedCredential {
  issuerJwt: string;
  credentialId: string;
  roots: FieldNode[];
  nodes: FieldNode[];
}

type Json = Record<string, unknown>;

function decodeB64u(text: string): string {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export async function parseCredential(token: string): Promise<ParsedCredential> {
  const [issuerJwt, ...rest] = token.split("~");
  const payload = JSON.parse(decodeB64u(issuerJwt.split(".")[1])) as Json;
  const byDigest = new Map<string, { raw: string; decoded: unknown[] }>();
  for (const raw of rest.filter(Boolean)) {
    byDigest.set(await sha256B64u(raw), { raw, decoded: JSON.parse(decodeB64u(raw)) });
  }

  const nodes: FieldNode[] = [];
  const roots: FieldNode[] = [];

  const attach = (node: FieldNode) => {
    nodes.push(node);
    (node.parent ? node.parent.children : roots).push(node);
  };

  const walk = (value: unknown, path: string, parent: FieldNode | null): void => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        const child = `${path}[${index}]`;
        const digest = (item as Json | null)?.["..."] as string | undefined;
        const found = digest ? byDigest.get(digest) : undefined;
        if (found) {
          const element = found.decoded[1] as Json;
          const node: FieldNode = {
            path: child,
            name: String(element.type ?? "item"),
            value: element,
            raw: found.raw,
            parent,
            children: [],
          };
          attach(node);
          walk(element, child, node);
        } else {
          walk(item, child, parent);
        }
      });
      return;
    }
    if (value === null || typeof value !== "object") return;
    const object = value as Json;
    for (const digest of (object._sd as string[] | undefined) ?? []) {
      const found = byDigest.get(digest);
      if (!found) continue;
      const [, name, disclosed] = found.decoded as [string, string, unknown];
      const child = path ? `${path}.${name}` : name;
      const node: FieldNode = { path: child, name, value: disclosed, raw: found.raw, parent, children: [] };
      attach(node);
      walk(disclosed, child, node);
    }
    for (const [key, nested] of Object.entries(object)) {
      if (key !== "_sd") walk(nested, path ? `${path}.${key}` : key, parent);
    }
  };

  walk(payload.customerProfile, "customerProfile", null);
  walk(payload.customerDetails, "customerDetails", null);
  const byRank = (a: FieldNode, b: FieldNode) => fieldRank(a.name) - fieldRank(b.name);
  roots.sort(byRank);
  nodes.forEach((node) => node.children.sort(byRank));
  return { issuerJwt, credentialId: String(payload.jti), roots, nodes };
}

/** A field can only be shown if the item that contains it is shown too. */
export function withAncestors(selected: Set<string>, nodes: FieldNode[]): Set<string> {
  const closed = new Set(selected);
  for (const node of nodes) {
    if (!selected.has(node.path)) continue;
    for (let parent = node.parent; parent; parent = parent.parent) closed.add(parent.path);
  }
  return closed;
}

export function withoutDescendants(selected: Set<string>, node: FieldNode): Set<string> {
  const next = new Set(selected);
  const remove = (current: FieldNode) => {
    next.delete(current.path);
    current.children.forEach(remove);
  };
  remove(node);
  return next;
}

export type FieldGroup = "connection" | "assets" | "personal";

export function fieldGroup(node: FieldNode): FieldGroup {
  if (node.path.includes("energyResources")) return "assets";
  if (node.path.includes("consumptionProfiles")) return "connection";
  return "personal";
}

/** The fields a verifier actually receives: items with nothing ticked beneath them count too. */
export function selectedLeaves(chosen: FieldNode[], selected: Set<string>): FieldNode[] {
  return chosen.filter((node) => !node.children.some((child) => selected.has(child.path)));
}

export type PresetName = "lender" | "marketplace" | "subsidy";

export function presetPaths(preset: PresetName, nodes: FieldNode[]): Set<string> {
  const pick = (test: (node: FieldNode) => boolean) => nodes.filter(test).map((node) => node.path);
  const solarAttribute = (node: FieldNode, names: string[]) =>
    node.parent?.name === "SOLAR_PV" && names.includes(node.name);
  const selected =
    preset === "lender"
      ? pick((n) => n.name === "sanctionedLoad")
      : preset === "marketplace"
        ? pick((n) => solarAttribute(n, ["maxExport", "inspection"]))
        : pick(
            (n) =>
              ["fullName", "customerNumber", "sanctionedLoad"].includes(n.name) ||
              solarAttribute(n, ["maxExport", "inspection", "commissioningDate"]),
          );
  return withAncestors(new Set(selected), nodes);
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return value.slice(0, 10);
  if (typeof value !== "object") return String(value);
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  const object = value as Json;
  if ("value" in object && "unit" in object) return `${object.value} ${object.unit}`;
  if ("result" in object) return [object.result, object.date].filter(Boolean).join(", ");
  if ("address" in object) return formatValue(object.address);
  if ("streetAddress" in object) {
    return ["streetAddress", "addressLocality", "addressRegion", "postalCode"]
      .map((key) => object[key])
      .filter(Boolean)
      .join(", ");
  }
  if ("subjectId" in object) return String(object.subjectId);
  return "";
}
