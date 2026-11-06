"""SQLite schema. Passport metadata and logs only.

No signed credential, name, address or mobile number is stored here: the consumer holds
the credential and the DISCOM's systems hold the master data. The connection, meter and
btm_asset rows are a non-personal snapshot taken at issuance.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ConsumerRef(Base):
    __tablename__ = "consumer_ref"

    id: Mapped[int] = mapped_column(primary_key=True)
    consumer_no: Mapped[str] = mapped_column(String(32), unique=True)
    consumer_did: Mapped[str] = mapped_column(String(255))
    mobile_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    discom_id: Mapped[str] = mapped_column(String(64))


class Connection(Base):
    __tablename__ = "connection"

    id: Mapped[int] = mapped_column(primary_key=True)
    consumer_ref_id: Mapped[int] = mapped_column(ForeignKey("consumer_ref.id"), unique=True)
    service_conn_no: Mapped[str] = mapped_column(String(64))
    tariff_category: Mapped[str] = mapped_column(String(32))
    sanctioned_load_kw: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16))

    consumer: Mapped[ConsumerRef] = relationship()
    meters: Mapped[list[Meter]] = relationship(cascade="all, delete-orphan")
    assets: Mapped[list[BtmAsset]] = relationship(cascade="all, delete-orphan")


class Meter(Base):
    __tablename__ = "meter"

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("connection.id"))
    meter_no: Mapped[str] = mapped_column(String(64))
    meter_did: Mapped[str] = mapped_column(String(255))
    type: Mapped[str] = mapped_column(String(16))  # consumption / generation


class BtmAsset(Base):
    __tablename__ = "btm_asset"

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("connection.id"))
    asset_did: Mapped[str] = mapped_column(String(255))
    asset_type: Mapped[str] = mapped_column(String(32))
    capacity_kw: Mapped[float | None] = mapped_column(Float)
    inspection_status: Mapped[str] = mapped_column(String(16))  # pass / fail / conditional / none
    inspected_on: Mapped[str | None] = mapped_column(String(10))


class Passport(Base):
    """One row per issued Passport. The credential itself is never stored."""

    __tablename__ = "passport"

    id: Mapped[int] = mapped_column(primary_key=True)
    credential_id: Mapped[str] = mapped_column(String(64), unique=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("connection.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    revocation_hash: Mapped[str] = mapped_column(String(64), unique=True)
    proof_format: Mapped[str] = mapped_column(String(16))  # sd-jwt-vc / jws-2020
    holder_did: Mapped[str] = mapped_column(String(1024))
    binding: Mapped[str] = mapped_column(String(16))  # wallet / discom-did / digilocker
    status: Mapped[str] = mapped_column(String(16), default="active")  # active / revoked
    reissue_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload_hash: Mapped[str] = mapped_column(String(64))

    connection: Mapped[Connection] = relationship()


class RevocationEvent(Base):
    __tablename__ = "revocation_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    passport_id: Mapped[int] = mapped_column(ForeignKey("passport.id"), index=True)
    reason: Mapped[str] = mapped_column(String(32))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))


class ShareSession(Base):
    __tablename__ = "share_session"

    id: Mapped[int] = mapped_column(primary_key=True)
    passport_id: Mapped[int] = mapped_column(ForeignKey("passport.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    disclosed_fields: Mapped[list[str]] = mapped_column(JSON)
    verifier_hint: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_count: Mapped[int] = mapped_column(Integer, default=0)


class VerificationLog(Base):
    __tablename__ = "verification_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    credential_id: Mapped[str | None] = mapped_column(String(64), index=True)
    verifier_did: Mapped[str | None] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(8))  # pass / fail
    failed_checks: Mapped[list[str]] = mapped_column(JSON, default=list)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    ip: Mapped[str | None] = mapped_column(String(64))


class ConsentRecord(Base):
    """IES conformance and DPDP Act 2023: consent captured on every issuance and disclosure."""

    __tablename__ = "consent_record"

    id: Mapped[int] = mapped_column(primary_key=True)
    consumer_ref_id: Mapped[int] = mapped_column(ForeignKey("consumer_ref.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(32))  # issue / share
    scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FieldMappingRow(Base):
    __tablename__ = "field_mapping"
    __table_args__ = (UniqueConstraint("ies_field", "source_column"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ies_field: Mapped[str] = mapped_column(String(128))
    source_system: Mapped[str] = mapped_column(String(32))
    source_column: Mapped[str] = mapped_column(String(64))
    transform_rule: Mapped[str] = mapped_column(String(32))


class AdminUser(Base):
    __tablename__ = "admin_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin / operator / auditor


Index("ix_passport_status", Passport.status)
