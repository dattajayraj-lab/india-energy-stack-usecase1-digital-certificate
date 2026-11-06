/** API client. Sessions live in sessionStorage, so they end with the tab. */

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Portal = "admin" | "consumer";

export interface StoredSession {
  token: string;
  role: string;
  subject: string;
}

const sessionKey = (portal: Portal) => `cep-session-${portal}`;

export function getSession(portal: Portal): StoredSession | null {
  if (typeof window === "undefined") return null;
  const raw = sessionStorage.getItem(sessionKey(portal));
  return raw ? (JSON.parse(raw) as StoredSession) : null;
}

export function setSession(portal: Portal, session: StoredSession): void {
  sessionStorage.setItem(sessionKey(portal), JSON.stringify(session));
}

export function clearSession(portal: Portal): void {
  sessionStorage.removeItem(sessionKey(portal));
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public flags: QualityFlag[] = [],
  ) {
    super(message);
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  portal?: Portal;
}

export async function api<T>(path: string, { method = "GET", body, portal }: RequestOptions = {}): Promise<T> {
  const session = portal ? getSession(portal) : null;
  const response = await fetch(`${API_URL}/api/v1${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(session ? { Authorization: `Bearer ${session.token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (response.status === 204) return undefined as T;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    if (typeof detail === "string") throw new ApiError(response.status, detail);
    if (detail?.message) throw new ApiError(response.status, detail.message, detail.flags);
    throw new ApiError(response.status, "Something went wrong. Try again.");
  }
  return data as T;
}

export interface Passport {
  id: number;
  credential_id: string;
  consumer_no: string;
  version: number;
  status: "active" | "revoked";
  proof_format: string;
  binding: "wallet" | "discom-did" | "digilocker";
  holder_did: string;
  issued_at: string;
  expires_at: string;
  reissue_pending: boolean;
}

export interface PassportDetail extends Passport {
  connection: {
    service_conn_no: string;
    tariff_category: string;
    sanctioned_load_kw: number;
    status: string;
    meters: { meter_no: string; meter_did: string; type: string }[];
    assets: {
      asset_did: string;
      asset_type: string;
      capacity_kw: number | null;
      inspection_status: string;
      inspected_on: string | null;
    }[];
  };
}

export interface IssueResult {
  passport: Passport;
  credential: string | Record<string, unknown>;
  format: string;
}

export interface Share {
  id: number;
  passport_id: number;
  disclosed_fields: string[];
  verifier_hint: string | null;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  used_count: number;
}

export interface QualityFlag {
  code: string;
  severity: "blocker" | "warning";
  field: string;
  message: string;
}

export interface ConsumerSummary {
  consumer_no: string;
  name: string;
  service_conn_no: string;
  tariff_category: string;
  city: string;
  passport_status: string | null;
  passport_id: number | null;
}

export interface Preview {
  consumer_no: string;
  issuable: boolean;
  flags: QualityFlag[];
  subject: {
    customerProfile: {
      customerNumber: string;
      energyResources: { id: string; type: string; attributes?: Record<string, unknown> }[];
      consumptionProfiles: Record<string, unknown>[];
    };
    customerDetails: Record<string, unknown>;
  };
  active_passport: Passport | null;
}

export interface Dashboard {
  issued: number;
  active: number;
  revoked: number;
  verified_pass: number;
  verified_fail: number;
  pending_reissue: number;
  by_day: { day: string; issued: number; verified: number }[];
  revocations_by_reason: Record<string, number>;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface AuditRow {
  id: number;
  actor: string;
  action: string;
  entity: string;
  entity_id: string;
  at: string;
  ip: string | null;
}

export interface VerificationRow {
  id: number;
  credential_id: string | null;
  verifier_did: string | null;
  result: "pass" | "fail";
  failed_checks: string[];
  checked_at: string;
}

export interface VerifyCheck {
  id: string;
  status: "pass" | "fail" | "warn" | "skip";
  detail: string;
}

export interface VerifyResult {
  valid: boolean;
  format: string;
  issuer: string | null;
  credential_id: string | null;
  valid_until: string | null;
  checks: VerifyCheck[];
  disclosed: Record<string, unknown>;
  disclosed_paths: string[];
}
