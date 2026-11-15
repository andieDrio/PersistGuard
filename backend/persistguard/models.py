from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, LargeBinary, SmallInteger, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    identity_issuer: Mapped[str | None] = mapped_column(Text(collation="C"))
    identity_subject: Mapped[str | None] = mapped_column(Text(collation="C"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    organization: Mapped[Organization] = relationship()

    __table_args__ = (
        CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="ck_users_role"),
        CheckConstraint(
            "(identity_issuer IS NULL) = (identity_subject IS NULL)", name="ck_users_identity_pair"
        ),
        UniqueConstraint("identity_issuer", "identity_subject", name="uq_users_identity"),
        Index("uq_users_org_email", organization_id, func.lower(email), unique=True),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    hostname: Mapped[str] = mapped_column(Text)
    os_family: Mapped[str] = mapped_column(Text)
    os_version: Mapped[str | None] = mapped_column(Text)
    agent_version: Mapped[str | None] = mapped_column(Text)
    device_public_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(Text, server_default="pending")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    organization: Mapped[Organization] = relationship()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_endpoints_id_org"),
        UniqueConstraint("organization_id", "device_public_key", name="uq_endpoints_org_device_key"),
        Index("ix_endpoints_organization_id", "organization_id"),
    )


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    field: Mapped[str] = mapped_column(Text)
    pattern: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(SmallInteger)
    revision: Mapped[int] = mapped_column(server_default="1")
    draft_version: Mapped[int] = mapped_column(server_default="1")
    published_version: Mapped[int | None] = mapped_column()
    tested: Mapped[bool] = mapped_column(server_default="false")
    enabled: Mapped[bool] = mapped_column(server_default="false")

    __table_args__ = (
        CheckConstraint("source IN ('registry', 'scheduled_tasks', 'services')", name="ck_detection_rules_source"),
        CheckConstraint("field IN ('path', 'command')", name="ck_detection_rules_field"),
        CheckConstraint("score BETWEEN 1 AND 100", name="ck_detection_rules_score"),
        CheckConstraint("NOT enabled OR published_version IS NOT NULL", name="ck_detection_rules_published"),
        Index("ix_detection_rules_org", "organization_id"),
    )


class PublishedDetectionRule(Base):
    __tablename__ = "published_detection_rules"

    rule_id: Mapped[UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    field: Mapped[str] = mapped_column(Text)
    pattern: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(SmallInteger)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CaseRecord(Base):
    __tablename__ = "cases"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="new")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('new', 'in_progress', 'resolved')", name="ck_cases_status"),
        UniqueConstraint("id", "organization_id", name="uq_cases_id_org"),
        Index("ix_cases_org_created", "organization_id", "created_at", "id"),
    )


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("kind IN ('ip', 'domain', 'sha256', 'url')", name="ck_indicators_kind"),
        UniqueConstraint("organization_id", "kind", "value", name="uq_indicators_org_kind_value"),
        Index("ix_indicators_org_created", "organization_id", "created_at", "id"),
    )


class CoverageValidation(Base):
    __tablename__ = "coverage_validations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    use_case_id: Mapped[str] = mapped_column(Text)
    result: Mapped[str] = mapped_column(Text)
    tested_on: Mapped[date] = mapped_column()
    reference: Mapped[str] = mapped_column(Text)
    recorded_by: Mapped[UUID] = mapped_column()
    recorded_role: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("result IN ('passed', 'failed', 'inconclusive')", name="ck_coverage_validations_result"),
        CheckConstraint("recorded_role IN ('admin', 'analyst')", name="ck_coverage_validations_role"),
        UniqueConstraint("organization_id", "use_case_id", "tested_on", "result", "reference", name="uq_coverage_validation_test"),
        Index("ix_coverage_validations_scope_date", "organization_id", "use_case_id", "tested_on", "recorded_at", "id"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    # Keep historical identifiers even if the account or organization is deleted.
    organization_id: Mapped[UUID] = mapped_column()
    actor_id: Mapped[UUID] = mapped_column()
    target_id: Mapped[UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(SmallInteger)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("status_code BETWEEN 100 AND 599", name="ck_audit_events_status_code"),
        Index("ix_audit_events_org_time", "organization_id", "occurred_at"),
    )


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    token_hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.statement_timestamp()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("octet_length(token_hash) = 32", name="ck_enrollment_tokens_hash_length"),
        CheckConstraint("expires_at > created_at", name="ck_enrollment_tokens_expiry"),
        Index("ix_enrollment_tokens_organization_id", "organization_id"),
    )


class AgentCredential(Base):
    __tablename__ = "agent_credentials"

    certificate_serial: Mapped[str] = mapped_column(Text, primary_key=True)
    endpoint_id: Mapped[UUID] = mapped_column(ForeignKey("endpoints.id"), index=True)
    certificate_pem: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaces_serial: Mapped[str | None] = mapped_column(
        Text, ForeignKey("agent_credentials.certificate_serial", name="fk_agent_credentials_predecessor")
    )

    __table_args__ = (
        UniqueConstraint("replaces_serial", name="uq_agent_credentials_replaces_serial"),
        Index(
            "uq_agent_credentials_current_endpoint",
            endpoint_id,
            unique=True,
            postgresql_where=revoked_at.is_(None) & superseded_at.is_(None),
        ),
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column()
    endpoint_id: Mapped[UUID] = mapped_column()
    requested_by: Mapped[UUID] = mapped_column()
    scan_type: Mapped[str] = mapped_column(Text)
    result: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text, server_default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(["endpoint_id", "organization_id"], ["endpoints.id", "endpoints.organization_id"]),
        UniqueConstraint("id", "organization_id", name="uq_scan_jobs_id_org"),
        CheckConstraint("scan_type = 'persistence_full_scan'", name="ck_scan_jobs_type"),
        CheckConstraint(
            "status IN ('queued', 'dispatched', 'acknowledged', 'running', 'uploading', 'analyzing', "
            "'completed', 'partial', 'failed', 'canceled')", name="ck_scan_jobs_status",
        ),
        Index(
            "uq_scan_jobs_open_endpoint", endpoint_id, unique=True,
            postgresql_where=status.not_in(("completed", "partial", "failed", "canceled")),
        ),
        Index("ix_scan_jobs_org_created", organization_id, created_at, id),
    )


class CaseFinding(Base):
    __tablename__ = "case_findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column()
    case_id: Mapped[UUID] = mapped_column()
    scan_job_id: Mapped[UUID] = mapped_column()
    source: Mapped[str] = mapped_column(Text)
    artifact_index: Mapped[int] = mapped_column()
    evidence: Mapped[dict] = mapped_column(JSONB)
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(["case_id", "organization_id"], ["cases.id", "cases.organization_id"]),
        ForeignKeyConstraint(["scan_job_id", "organization_id"], ["scan_jobs.id", "scan_jobs.organization_id"]),
        UniqueConstraint("case_id", "scan_job_id", "source", "artifact_index", name="uq_case_findings_artifact"),
        CheckConstraint("source IN ('registry', 'scheduled_tasks', 'services') AND artifact_index >= 0",
                        name="ck_case_findings_artifact"),
        Index("ix_case_findings_case_attached", "case_id", "attached_at", "id"),
        Index("ix_case_findings_scan_job", "scan_job_id"),
    )

