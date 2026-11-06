"""Request and response models: the frozen OpenAPI contract for /api/v1."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ConsumerNo = str
MAX_CREDENTIAL_CHARS = 200_000


class OtpRequest(BaseModel):
    consumer_no: ConsumerNo = Field(min_length=4, max_length=32)


class OtpRequested(BaseModel):
    sent: bool = True
    expires_in: int
    dev_otp: str | None = Field(None, description="Only present outside production")


class OtpVerify(BaseModel):
    consumer_no: ConsumerNo = Field(min_length=4, max_length=32)
    otp: str = Field(pattern=r"^\d{6}$")


class AdminLogin(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


class Session(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - the OAuth token type, not a secret
    role: str
    expires_in: int


class NonceOut(BaseModel):
    nonce: str
    audience: str
    expires_in: int


class IssueIn(BaseModel):
    consumer_no: ConsumerNo | None = Field(None, description="Required for staff; ignored for consumers")
    holder_did: str | None = Field(None, max_length=1024)
    holder_proof: str | None = Field(None, max_length=4096)
    consent: bool = Field(description="The consumer has agreed to this issuance")


class PassportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    credential_id: str
    consumer_no: str
    version: int
    status: str
    proof_format: str
    binding: str
    holder_did: str
    issued_at: datetime
    expires_at: datetime
    reissue_pending: bool


class IssueOut(BaseModel):
    passport: PassportOut
    credential: str | dict[str, Any]
    format: str


class MeterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    meter_no: str
    meter_did: str
    type: str


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_did: str
    asset_type: str
    capacity_kw: float | None
    inspection_status: str
    inspected_on: str | None


class ConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    service_conn_no: str
    tariff_category: str
    sanctioned_load_kw: float
    status: str
    meters: list[MeterOut]
    assets: list[AssetOut]


class PassportDetail(PassportOut):
    connection: ConnectionOut


class RevokeIn(BaseModel):
    reason: Literal["meter_swap", "load_change", "der_change", "request"]


class ReissueIn(BaseModel):
    reason: Literal["meter_swap", "load_change", "der_change", "request", "holder_rebind"] = "holder_rebind"
    holder_did: str | None = Field(None, max_length=1024)
    holder_proof: str | None = Field(None, max_length=4096)


class ShareIn(BaseModel):
    presentation: str = Field(max_length=MAX_CREDENTIAL_CHARS)
    disclosed_fields: list[str] = Field(max_length=500)
    ttl_seconds: int = Field(ge=60)
    verifier_hint: str | None = Field(None, max_length=128)
    consent: bool


class ShareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    passport_id: int
    disclosed_fields: list[str]
    verifier_hint: str | None
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    used_count: int


class ShareCreated(BaseModel):
    share: ShareOut
    url: str
    token: str


class SharedPresentation(BaseModel):
    presentation: str


class VerifyIn(BaseModel):
    credential: str | dict[str, Any]
    expected_nonce: str | None = Field(None, max_length=256)
    expected_audience: str | None = Field(None, max_length=256)
    verifier_did: str | None = Field(None, max_length=255)


class CheckOut(BaseModel):
    id: str
    status: Literal["pass", "fail", "warn", "skip"]
    detail: str


class VerifyOut(BaseModel):
    valid: bool
    format: str
    issuer: str | None
    credential_id: str | None
    valid_until: str | None
    checks: list[CheckOut]
    disclosed: dict[str, Any]
    disclosed_paths: list[str]


class SourceChangeIn(BaseModel):
    event_id: str = Field(min_length=1, max_length=64)
    consumer_no: ConsumerNo = Field(max_length=32)
    event: Literal["meter_swap", "load_change", "der_change"]


class SourceChangeOut(BaseModel):
    action: Literal["revoked_pending_reissue", "no_active_passport", "duplicate_event"]
    passport_id: int | None = None


class ConsumerSummary(BaseModel):
    consumer_no: str
    name: str
    service_conn_no: str
    tariff_category: str
    city: str
    passport_status: str | None
    passport_id: int | None


class FlagOut(BaseModel):
    code: str
    severity: Literal["blocker", "warning"]
    field: str
    message: str


class PreviewOut(BaseModel):
    consumer_no: str
    issuable: bool
    flags: list[FlagOut]
    subject: dict[str, Any]
    active_passport: PassportOut | None


class DayCount(BaseModel):
    day: str
    issued: int
    verified: int


class DashboardOut(BaseModel):
    issued: int
    active: int
    revoked: int
    verified_pass: int
    verified_fail: int
    pending_reissue: int
    by_day: list[DayCount]
    revocations_by_reason: dict[str, int]


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor: str
    action: str
    entity: str
    entity_id: str
    at: datetime
    ip: str | None


class VerificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    credential_id: str | None
    verifier_did: str | None
    result: str
    failed_checks: list[str]
    checked_at: datetime


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int


class FieldMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ies_field: str
    source_system: str
    source_column: str
    transform_rule: str
