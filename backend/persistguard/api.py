import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from typing import Annotated, Literal
from uuid import UUID

from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, load_only

from persistguard.attack_coverage import CoverageUseCase, attack_coverage
from persistguard.auth import AuthenticatedUser, LocalIdentity, database_session, linked_account, local_identity
from persistguard.client_certificates import CertificateIssuanceError, issue_client_certificate
from persistguard.custom_rules import CustomRule
from persistguard.device_enrollment import router as device_enrollment_router
from persistguard.enrollment import TOKEN_LIFETIME, issue_enrollment_token
from persistguard.ioc_matching import IndicatorKind, build_ioc_index, normalize_indicator
from persistguard.models import AgentCredential, AuditEvent, CaseFinding, CaseRecord, CoverageValidation, DetectionRule, Endpoint, Indicator, Organization, PublishedDetectionRule, ScanJob, User
from persistguard.normalize_inventory import ArtifactCommand, Source
from persistguard.rotation import router as rotation_router
from persistguard.rule_yaml import MAX_RULE_YAML_BYTES, RuleDefinition, RuleYAMLError, export_rule_yaml, parse_rule_yaml
from persistguard.scan_assessment import assess_scan_report


app = FastAPI(title="PersistGuard")
app.include_router(device_enrollment_router)
app.include_router(rotation_router)

TERMINAL_SCAN_STATUSES = ("completed", "partial", "failed", "canceled")


@app.get("/healthz", tags=["Health"])
def health() -> dict[str, str]:
    return {"status": "ok"}


def coverage_catalog() -> list[CoverageUseCase]:
    try:
        return attack_coverage()
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=503, detail="XDR coverage baseline unavailable") from error


@app.get("/api/attack-coverage", tags=["Detection Rules"])
def get_attack_coverage(
    user: Annotated[AuthenticatedUser, Depends(local_identity)], response: Response,
) -> list[CoverageUseCase]:
    response.headers["Cache-Control"] = "no-store"
    return coverage_catalog()


@app.get("/api/me", tags=["Identity"])
def me(identity: Annotated[AuthenticatedUser, Depends(local_identity)], response: Response) -> LocalIdentity:
    response.headers["Cache-Control"] = "no-store"
    return LocalIdentity(identity.subject, identity.user_id, identity.organization_id)


@dataclass(frozen=True)
class UserSummary:
    id: UUID
    email: str
    role: str


def commit_audit_event(
    session: Session, actor: AuthenticatedUser, action: str, status_code: int, *, target_id: UUID | None = None
) -> None:
    statement = insert(AuditEvent.__table__).inline().values(
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        target_id=target_id,
        action=action,
        status_code=status_code,
    )
    try:
        session.execute(statement)
        session.commit()
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Audit log unavailable") from error


def require_admin(session: Session, user: AuthenticatedUser, action: str) -> None:
    if not user.organization_active or user.role != "admin":
        commit_audit_event(session, user, action, 403)
        detail = "Administrator access required" if user.organization_active else "No active local account"
        raise HTTPException(status_code=403, detail=detail)


def authorize_user_list(
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> AuthenticatedUser:
    require_admin(session, user, "users.list")
    return user


@app.get("/api/users", tags=["Users"])
def list_users(
    admin: Annotated[AuthenticatedUser, Depends(authorize_user_list)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> list[UserSummary]:
    statement = (
        select(User.id, User.email, User.role)
        .where(User.organization_id == admin.organization_id)
        .order_by(User.id)
        .limit(limit)
        .offset(offset)
    )
    users = [UserSummary(row.id, row.email, row.role) for row in session.execute(statement)]
    commit_audit_event(session, admin, "users.list", 200)
    response.headers["Cache-Control"] = "no-store"
    return users


@dataclass(frozen=True)
class EnrollmentInvitation:
    token: str = field(repr=False)
    organization_id: UUID
    expires_in_seconds: int


@app.post("/api/enrollment-tokens", tags=["Enrollment"], status_code=201)
def create_enrollment_token(
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> EnrollmentInvitation:
    action = "enrollment_tokens.issue"
    require_admin(session, user, action)
    try:
        token = issue_enrollment_token(session, user.organization_id)
    except ValueError as error:
        commit_audit_event(session, user, action, 403)
        raise HTTPException(status_code=403, detail="No active local account") from error
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Enrollment token issuance unavailable") from error

    commit_audit_event(session, user, action, 201)
    response.headers["Cache-Control"] = "no-store"
    return EnrollmentInvitation(token, user.organization_id, int(TOKEN_LIFETIME.total_seconds()))


@dataclass(frozen=True)
class DeviceCertificate:
    endpoint_id: UUID
    certificate_pem: str
    certificate_serial: str
    expires_at: datetime


@app.put("/api/endpoints/{endpoint_id}/client-certificate", tags=["Enrollment"], status_code=201,
         responses={200: {"model": DeviceCertificate, "description": "Existing client certificate"}})
def approve_device_certificate(
    endpoint_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> DeviceCertificate:
    action = "agent_credentials.issue"
    require_admin(session, user, action)
    response.headers["Cache-Control"] = "no-store"
    try:
        endpoint = session.scalar(
            select(Endpoint).where(
                Endpoint.id == endpoint_id, Endpoint.organization_id == user.organization_id,
            ).with_for_update()
        )
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")

        if endpoint.status == "approved":
            credential = session.scalar(select(AgentCredential).where(
                AgentCredential.endpoint_id == endpoint_id, AgentCredential.revoked_at.is_(None),
                AgentCredential.superseded_at.is_(None),
                AgentCredential.expires_at > datetime.now(timezone.utc),
            ))
            if credential is None:
                raise HTTPException(status_code=409, detail="Endpoint has no current certificate")
            response.status_code = 200
            return DeviceCertificate(endpoint_id, credential.certificate_pem,
                                     credential.certificate_serial, credential.expires_at.astimezone(timezone.utc))

        if endpoint.status != "pending" or endpoint.device_public_key is None:
            raise HTTPException(status_code=409, detail="Endpoint is not awaiting certificate approval")

        cert = issue_client_certificate(endpoint_id, endpoint.device_public_key)
        result = DeviceCertificate(endpoint_id, cert.public_bytes(Encoding.PEM).decode("ascii"),
                                   format(cert.serial_number, "x"), cert.not_valid_after_utc)
        session.add(AgentCredential(endpoint_id=endpoint_id, certificate_serial=result.certificate_serial,
                                    certificate_pem=result.certificate_pem, expires_at=result.expires_at))
        endpoint.status = "approved"
        commit_audit_event(session, user, action, 201, target_id=endpoint_id)
    except (CertificateIssuanceError, SQLAlchemyError) as error:
        raise HTTPException(status_code=503, detail="Client certificate issuance unavailable") from error
    return result


@app.post("/api/endpoints/{endpoint_id}/revoke", tags=["Enrollment"])
def revoke_endpoint(
    endpoint_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> dict[str, str]:
    action = "endpoints.revoke"
    require_admin(session, user, action)
    response.headers["Cache-Control"] = "no-store"
    result = {"endpoint_id": str(endpoint_id), "status": "revoked"}
    try:
        endpoint = session.scalar(select(Endpoint).where(
            Endpoint.id == endpoint_id, Endpoint.organization_id == user.organization_id,
        ).with_for_update())
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        if endpoint.status == "revoked":
            return result
        if endpoint.status != "approved":
            raise HTTPException(status_code=409, detail="Only approved endpoints can be revoked")

        endpoint.status = "revoked"
        session.execute(update(AgentCredential).where(
            AgentCredential.endpoint_id == endpoint_id, AgentCredential.revoked_at.is_(None),
        ).values(revoked_at=func.statement_timestamp()))
        session.execute(update(ScanJob).where(
            ScanJob.endpoint_id == endpoint_id, ScanJob.organization_id == user.organization_id,
            ScanJob.status.not_in(TERMINAL_SCAN_STATUSES),
        ).values(status="canceled", finished_at=func.statement_timestamp()))
        commit_audit_event(session, user, action, 200, target_id=endpoint_id)
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Endpoint revocation unavailable") from error
    return result


@dataclass(frozen=True)
class ScanJobSummary:
    id: UUID
    organization_id: UUID
    endpoint_id: UUID
    scan_type: str
    status: str
    created_at: datetime


@dataclass(frozen=True)
class ScanTarget:
    id: UUID
    hostname: str


@dataclass(frozen=True)
class ScanTargets:
    can_manage: bool
    can_onboard: bool
    endpoints: list[ScanTarget]


@app.get("/api/scan-targets", tags=["Scans"])
def list_scan_targets(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    query: Annotated[str, Query(max_length=253)] = "",
) -> ScanTargets:
    statement = select(Endpoint.id, Endpoint.hostname).where(
        Endpoint.organization_id == user.organization_id, Endpoint.status == "approved", Endpoint.os_family == "windows",
    )
    if query.strip():
        statement = statement.where(Endpoint.hostname.icontains(query.strip(), autoescape=True))
    targets = session.execute(statement.order_by(Endpoint.hostname, Endpoint.id).limit(100))
    response.headers["Cache-Control"] = "no-store"
    return ScanTargets(user.role in {"admin", "analyst"}, user.role == "admin",
                       [ScanTarget(row.id, row.hostname) for row in targets])


@dataclass(frozen=True)
class EndpointSummary:
    id: UUID
    hostname: str
    os_family: str
    status: str
    created_at: datetime
    has_device_key: bool


@app.get("/api/endpoints", tags=["Enrollment"])
def list_enrollment_endpoints(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    status: Literal["pending", "approved", "revoked"] = "pending",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> list[EndpointSummary]:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    statement = select(
        Endpoint.id, Endpoint.hostname, Endpoint.os_family, Endpoint.status, Endpoint.created_at,
        Endpoint.device_public_key.is_not(None).label("has_device_key"),
    ).where(Endpoint.organization_id == user.organization_id, Endpoint.status == status)
    statement = statement.order_by(Endpoint.created_at.desc(), Endpoint.id.desc()).limit(limit).offset(offset)
    response.headers["Cache-Control"] = "no-store"
    return [EndpointSummary(*row) for row in session.execute(statement)]


CaseStatus = Literal["new", "in_progress", "resolved"]
WorkspaceSection = Literal["dashboard", "cases", "endpoints", "tenant", "iocs"]
WORKSPACE_PAGE_SIZE = 50


@app.get("/api/workspace", tags=["Workspace"])
def workspace_snapshot(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    section: WorkspaceSection = "dashboard",
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
    case_query: Annotated[str, Query(max_length=200, pattern=r"^[^\x00]*$")] = "",
) -> dict:
    organization = session.get(Organization, user.organization_id)
    if organization is None or organization.status != "active":
        raise HTTPException(status_code=403, detail="No active local account")

    now = datetime.now(timezone.utc)
    recent = Endpoint.last_seen >= now - timedelta(minutes=2)
    approved = Endpoint.status == "approved"
    endpoint_scope = Endpoint.organization_id == organization.id
    case_scope = CaseRecord.organization_id == organization.id
    if section == "cases" and case_query.strip():
        case_scope = case_scope & CaseRecord.title.icontains(case_query.strip(), autoescape=True)
    indicator_scope = Indicator.organization_id == organization.id
    response.headers["Cache-Control"] = "no-store"

    result: dict = {"tenant": {"name": organization.name, "count": 1},
                    "can_manage": user.role in {"admin", "analyst"}}
    if section in ("dashboard", "endpoints"):
        counts = session.execute(select(
            func.count().label("total"),
            func.count().filter(Endpoint.created_at >= now - timedelta(hours=24)).label("new_installed"),
            func.count().filter(approved, recent).label("connected"),
            func.count().filter(approved, recent.is_not(True)).label("disconnected"),
        ).where(endpoint_scope)).mappings().one()
        result["endpoint_counts"] = dict(counts)
    if section in ("dashboard", "cases"):
        case_counts = {"new": 0, "in_progress": 0, "resolved": 0}
        case_counts.update(dict(session.execute(select(CaseRecord.status, func.count())
                                                 .where(case_scope).group_by(CaseRecord.status)).all()))
        result["case_counts"] = case_counts
    if section in ("dashboard", "iocs"):
        result["indicator_count"] = session.scalar(select(func.count()).select_from(Indicator).where(indicator_scope))

    if section == "endpoints":
        rows = session.execute(select(
            Endpoint.id, Endpoint.hostname, Endpoint.os_family, Endpoint.status, Endpoint.created_at,
            Endpoint.last_seen, (approved & recent).is_(True).label("connected"),
        ).where(endpoint_scope).order_by(Endpoint.created_at.desc(), Endpoint.id.desc())
            .offset(offset).limit(WORKSPACE_PAGE_SIZE)).mappings()
        result["endpoints"] = [dict(row) for row in rows]
    elif section == "cases":
        rows = session.scalars(select(CaseRecord).where(case_scope)
                               .order_by(CaseRecord.created_at.desc(), CaseRecord.id.desc())
                               .offset(offset).limit(WORKSPACE_PAGE_SIZE))
        result["cases"] = [{"id": row.id, "title": row.title, "status": row.status} for row in rows]
    elif section == "iocs":
        rows = session.scalars(select(Indicator).where(indicator_scope)
                               .order_by(Indicator.created_at.desc(), Indicator.id.desc())
                               .offset(offset).limit(WORKSPACE_PAGE_SIZE))
        result["indicators"] = [{"id": row.id, "kind": row.kind, "value": row.value} for row in rows]
    return result


class NewCase(BaseModel):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200, pattern=r"^[^\x00]+$")]


class CaseUpdate(BaseModel):
    status: CaseStatus


class NewIndicator(BaseModel):
    kind: IndicatorKind
    value: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]


def authorize_workspace_write(session: Session, user: AuthenticatedUser, action: str) -> None:
    if not user.organization_active or user.role not in {"admin", "analyst"}:
        commit_audit_event(session, user, action, 403)
        raise HTTPException(status_code=403, detail="Active admin or analyst access required")


ValidationResult = Literal["passed", "failed", "inconclusive"]
VALIDATION_PAGE_SIZE = 25


class NewCoverageValidation(BaseModel):
    result: ValidationResult
    tested_on: date
    reference: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500, pattern=r"^[^\x00]+$")]


class CoverageValidationSummary(NewCoverageValidation):
    id: UUID
    recorded_by: UUID
    recorded_role: Literal["admin", "analyst"]
    recorded_at: datetime


class CoverageValidationPage(BaseModel):
    can_manage: bool
    records: list[CoverageValidationSummary]
    next_offset: int | None


def verify_coverage_use_case(use_case_id: str) -> None:
    if not any(row.id == use_case_id for row in coverage_catalog()):
        raise HTTPException(status_code=404, detail="Coverage use case not found")


@app.get("/api/attack-coverage/{use_case_id}/validations", tags=["Detection Rules"])
def list_coverage_validations(
    use_case_id: str,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    offset: Annotated[int, Query(ge=0, le=2_147_483_621)] = 0,
) -> CoverageValidationPage:
    verify_coverage_use_case(use_case_id)
    statement = select(CoverageValidation).where(CoverageValidation.organization_id == user.organization_id,
                                                 CoverageValidation.use_case_id == use_case_id)
    rows = session.scalars(statement.order_by(CoverageValidation.tested_on.desc(), CoverageValidation.recorded_at.desc(),
                                             CoverageValidation.id.desc()).offset(offset).limit(VALIDATION_PAGE_SIZE + 1)).all()
    response.headers["Cache-Control"] = "no-store"
    return CoverageValidationPage(can_manage=user.role in {"admin", "analyst"},
                                  records=[CoverageValidationSummary.model_validate(row, from_attributes=True)
                                           for row in rows[:VALIDATION_PAGE_SIZE]],
                                  next_offset=offset + VALIDATION_PAGE_SIZE if len(rows) > VALIDATION_PAGE_SIZE else None)


@app.post("/api/attack-coverage/{use_case_id}/validations", tags=["Detection Rules"], status_code=201,
          responses={200: {"model": CoverageValidationSummary, "description": "Existing deployment test record"}})
def record_coverage_validation(
    use_case_id: str, data: NewCoverageValidation,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> CoverageValidationSummary:
    action = "coverage.validations.record"
    authorize_workspace_write(session, user, action)
    verify_coverage_use_case(use_case_id)
    statement = pg_insert(CoverageValidation).values(
        organization_id=user.organization_id, use_case_id=use_case_id, recorded_by=user.user_id,
        recorded_role=user.role, **data.model_dump(),
    ).on_conflict_do_nothing(constraint="uq_coverage_validation_test").returning(CoverageValidation)
    row = session.scalar(statement)
    response.headers["Cache-Control"] = "no-store"
    if row is not None:
        result = CoverageValidationSummary.model_validate(row, from_attributes=True)
        commit_audit_event(session, user, action, 201, target_id=row.id)
        return result
    existing = session.scalars(select(CoverageValidation).where(
        CoverageValidation.organization_id == user.organization_id, CoverageValidation.use_case_id == use_case_id,
        CoverageValidation.tested_on == data.tested_on, CoverageValidation.result == data.result,
        CoverageValidation.reference == data.reference,
    )).one()
    response.status_code = 200
    return CoverageValidationSummary.model_validate(existing, from_attributes=True)


@app.post("/api/workspace/cases", tags=["Workspace"], status_code=201)
def create_case(
    data: NewCase,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    action = "cases.create"
    authorize_workspace_write(session, user, action)
    record = CaseRecord(organization_id=user.organization_id, title=data.title)
    session.add(record)
    session.flush()
    result = {"id": record.id, "title": record.title, "status": record.status}
    commit_audit_event(session, user, action, 201, target_id=record.id)
    return result


@app.patch("/api/workspace/cases/{case_id}", tags=["Workspace"])
def update_case(
    case_id: UUID,
    data: CaseUpdate,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    action = "cases.update"
    authorize_workspace_write(session, user, action)
    row = session.execute(update(CaseRecord).where(CaseRecord.id == case_id,
                                                  CaseRecord.organization_id == user.organization_id)
                          .values(status=data.status).returning(CaseRecord.id, CaseRecord.title, CaseRecord.status)
                          ).mappings().one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Case not found")
    commit_audit_event(session, user, action, 200, target_id=case_id)
    return dict(row)


@app.post("/api/workspace/iocs", tags=["Workspace"], status_code=201)
def add_indicator(
    data: NewIndicator,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    action = "indicators.create"
    authorize_workspace_write(session, user, action)
    try:
        value = normalize_indicator(data.kind, data.value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Enter a valid indicator for the selected type") from error
    indicator = Indicator(organization_id=user.organization_id, kind=data.kind, value=value)
    session.add(indicator)
    try:
        session.flush()
    except IntegrityError as error:
        raise HTTPException(status_code=409, detail="Indicator already exists") from error
    result = {"id": indicator.id, "kind": indicator.kind, "value": indicator.value}
    commit_audit_event(session, user, action, 201, target_id=indicator.id)
    return result


class RuleRevision(BaseModel):
    revision: Annotated[int, Field(ge=1, strict=True)]


class RuleEdit(RuleDefinition, RuleRevision):
    pass


class RuleActivation(RuleRevision):
    enabled: bool


class RuleSample(BaseModel):
    path: Annotated[str, StringConstraints(max_length=2048)]
    command: Annotated[str, StringConstraints(max_length=4096)] = ""


class RuleTest(RuleRevision):
    samples: Annotated[list[RuleSample], Field(min_length=1, max_length=20)]


class RuleSummary(RuleDefinition, RuleRevision):
    id: UUID
    tested: bool
    enabled: bool
    draft_version: int
    published_version: int | None


class PublishedRuleSummary(RuleDefinition):
    version: int
    published_at: datetime | None


class RuleList(BaseModel):
    can_manage: bool
    rules: list[RuleSummary]


class RuleTestResult(BaseModel):
    rule: RuleSummary
    matched_indices: list[int]


RULE_LIMIT = 100


def summarize_rule(rule: DetectionRule) -> RuleSummary:
    return RuleSummary.model_validate(rule, from_attributes=True)


def matching_rule(rule: DetectionRule | PublishedDetectionRule) -> CustomRule:
    return CustomRule(rule.name, rule.source, rule.field, rule.pattern, rule.score)


def rule_for_update(session: Session, user: AuthenticatedUser, rule_id: UUID, revision: int, action: str) -> DetectionRule:
    require_admin(session, user, action)
    rule = session.scalar(select(DetectionRule).where(DetectionRule.id == rule_id,
                                                     DetectionRule.organization_id == user.organization_id).with_for_update())
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    if rule.revision != revision:
        raise HTTPException(status_code=409, detail="This rule changed. Refresh the rules and try again.")
    return rule


@app.get("/api/detection-rules", tags=["Detection Rules"])
def list_detection_rules(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> RuleList:
    rules = session.scalars(select(DetectionRule).where(DetectionRule.organization_id == user.organization_id)
                            .order_by(DetectionRule.name, DetectionRule.id))
    response.headers["Cache-Control"] = "no-store"
    return RuleList(can_manage=user.role == "admin", rules=[summarize_rule(rule) for rule in rules])


@app.get("/api/detection-rules/{rule_id}/versions", tags=["Detection Rules"])
def list_detection_rule_versions(
    rule_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    before: Annotated[int | None, Query(ge=1)] = None,
) -> list[PublishedRuleSummary]:
    rule = session.scalar(select(DetectionRule.id).where(DetectionRule.id == rule_id,
                                                        DetectionRule.organization_id == user.organization_id))
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    statement = select(PublishedDetectionRule).where(PublishedDetectionRule.rule_id == rule)
    if before is not None:
        statement = statement.where(PublishedDetectionRule.version < before)
    response.headers["Cache-Control"] = "no-store"
    return [PublishedRuleSummary.model_validate(item, from_attributes=True) for item in session.scalars(
        statement.order_by(PublishedDetectionRule.version.desc()).limit(25))]


class RuleYAMLExport(BaseModel):
    filename: str
    yaml: str


@app.get("/api/detection-rules/{rule_id}/export", tags=["Detection Rules"])
def export_detection_rule(
    rule_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    version: Annotated[int | None, Query(ge=1, le=2_147_483_647)] = None,
    revision: Annotated[int | None, Query(ge=1, le=2_147_483_647)] = None,
) -> RuleYAMLExport:
    action = "detection_rules.export.published" if version is not None else "detection_rules.export.draft"
    require_admin(session, user, action)
    rule = session.scalar(select(DetectionRule).where(DetectionRule.id == rule_id,
                                                     DetectionRule.organization_id == user.organization_id))
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    if version is None:
        if revision is not None and revision != rule.revision:
            raise HTTPException(status_code=409, detail="This rule changed. Refresh the rules before exporting.")
        definition = RuleDefinition.model_validate(rule, from_attributes=True)
        label = f"draft-v{rule.draft_version}"
    else:
        published = session.get(PublishedDetectionRule, (rule_id, version))
        if published is None:
            raise HTTPException(status_code=404, detail="Published rule version not found")
        definition = RuleDefinition.model_validate(published, from_attributes=True)
        label = f"published-v{published.version}"
    result = RuleYAMLExport(filename=f"persistguard-rule-{rule_id}-{label}.yaml", yaml=export_rule_yaml(definition))
    commit_audit_event(session, user, action, 200, target_id=rule_id)
    response.headers["Cache-Control"] = "no-store"
    return result


def save_rule_draft(data: RuleDefinition, user: AuthenticatedUser, session: Session, action: str) -> RuleSummary:
    organization = session.scalar(select(Organization).where(Organization.id == user.organization_id).with_for_update())
    if organization is None or organization.status != "active":
        raise HTTPException(status_code=403, detail="No active local account")
    count = session.scalar(select(func.count()).select_from(DetectionRule)
                           .where(DetectionRule.organization_id == user.organization_id))
    if count >= RULE_LIMIT:
        raise HTTPException(status_code=409, detail=f"This tenant already has {RULE_LIMIT} rules")
    rule = DetectionRule(organization_id=user.organization_id, **data.model_dump())
    session.add(rule)
    session.flush()
    result = summarize_rule(rule)
    commit_audit_event(session, user, action, 201, target_id=rule.id)
    return result


@app.post("/api/detection-rules", tags=["Detection Rules"], status_code=201)
def create_detection_rule(
    data: RuleDefinition,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleSummary:
    action = "detection_rules.create"
    require_admin(session, user, action)
    return save_rule_draft(data, user, session, action)


class RuleYAMLRequest(BaseModel):
    yaml: Annotated[str, StringConstraints(min_length=1, max_length=MAX_RULE_YAML_BYTES)]


def validated_rule_yaml(data: RuleYAMLRequest) -> RuleDefinition:
    try:
        return parse_rule_yaml(data.yaml)
    except RuleYAMLError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/api/detection-rules/import/validate", tags=["Detection Rules"])
def validate_detection_rule_yaml(
    data: RuleYAMLRequest,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleDefinition:
    require_admin(session, user, "detection_rules.import.validate")
    return validated_rule_yaml(data)


@app.post("/api/detection-rules/import", tags=["Detection Rules"], status_code=201)
def import_detection_rule_yaml(
    data: RuleYAMLRequest,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleSummary:
    action = "detection_rules.import"
    require_admin(session, user, action)
    return save_rule_draft(validated_rule_yaml(data), user, session, action)


@app.put("/api/detection-rules/{rule_id}", tags=["Detection Rules"])
def edit_detection_rule(
    rule_id: UUID, data: RuleEdit,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleSummary:
    action = "detection_rules.edit"
    rule = rule_for_update(session, user, rule_id, data.revision, action)
    changes = data.model_dump(exclude={"revision"})
    if any(getattr(rule, key) != value for key, value in changes.items()):
        for key, value in changes.items():
            setattr(rule, key, value)
        rule.revision += 1
        rule.draft_version += 1
        rule.tested = False
        result = summarize_rule(rule)
        commit_audit_event(session, user, action, 200, target_id=rule_id)
        return result
    return summarize_rule(rule)


@app.post("/api/detection-rules/{rule_id}/test", tags=["Detection Rules"])
def test_detection_rule(
    rule_id: UUID, data: RuleTest,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleTestResult:
    action = "detection_rules.test"
    rule = rule_for_update(session, user, rule_id, data.revision, action)
    condition = matching_rule(rule)
    matches = [index for index, sample in enumerate(data.samples)
               if condition.matches(sample.path, [ArtifactCommand(command_line=sample.command)] if sample.command else [])]
    rule.tested = rule.tested or bool(matches)
    result = RuleTestResult(rule=summarize_rule(rule), matched_indices=matches)
    commit_audit_event(session, user, action, 200, target_id=rule_id)
    return result


@app.put("/api/detection-rules/{rule_id}/activation", tags=["Detection Rules"])
def set_detection_rule_activation(
    rule_id: UUID, data: RuleActivation,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleSummary:
    action = "detection_rules.publish" if data.enabled else "detection_rules.disable"
    rule = rule_for_update(session, user, rule_id, data.revision, action)
    if data.enabled and not rule.tested:
        raise HTTPException(status_code=409, detail="Test this version with a matching sample before enabling it")
    pending_draft = rule.published_version != rule.draft_version
    if data.enabled == rule.enabled and (not data.enabled or not pending_draft):
        return summarize_rule(rule)
    if data.enabled and pending_draft:
        definition = RuleDefinition.model_validate(rule, from_attributes=True)
        session.add(PublishedDetectionRule(rule_id=rule.id, version=rule.draft_version,
                                           published_at=datetime.now(timezone.utc), **definition.model_dump()))
        rule.published_version = rule.draft_version
    rule.enabled = data.enabled
    rule.revision += 1
    result = summarize_rule(rule)
    commit_audit_event(session, user, action, 200, target_id=rule_id)
    return result



class RuleRollback(BaseModel):
    revision: int = Field(ge=1)
    version: int = Field(ge=1)


@app.post("/api/detection-rules/{rule_id}/rollback", tags=["Detection Rules"])
def rollback_detection_rule(
    rule_id: UUID, data: RuleRollback,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
) -> RuleSummary:
    action = "detection_rules.rollback"
    rule = rule_for_update(session, user, rule_id, data.revision, action)
    if rule.published_version is None:
        raise HTTPException(status_code=409, detail="No published version to restore")
    if data.version == rule.published_version and rule.enabled:
        raise HTTPException(status_code=409, detail="This version is already active")
    previous = session.get(PublishedDetectionRule, (rule.id, data.version))
    if previous is None:
        raise HTTPException(status_code=404, detail="Published rule version not found")
    # Keep draft content and immutable published history intact. Only switch
    # the active published-version pointer; scan assessments read that pointer.
    rule.published_version = previous.version
    rule.enabled = True
    rule.revision += 1
    result = summarize_rule(rule)
    commit_audit_event(session, user, action, 200, target_id=rule_id)
    return result


def summarize_scan_job(job: ScanJob) -> ScanJobSummary:
    return ScanJobSummary(job.id, job.organization_id, job.endpoint_id, job.scan_type, job.status, job.created_at)


@app.post("/api/endpoints/{endpoint_id}/scan-jobs", tags=["Scans"], status_code=201,
          responses={200: {"model": ScanJobSummary, "description": "Existing open scan job"}})
def queue_scan_job(
    endpoint_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScanJobSummary:
    if not user.organization_active or user.role not in {"admin", "analyst"}:
        commit_audit_event(session, user, "scan_jobs.queue", 403)
        raise HTTPException(status_code=403, detail="Scan scheduling requires an active admin or analyst account")

    response.headers["Cache-Control"] = "no-store"
    try:
        endpoint = session.scalar(select(Endpoint).where(
            Endpoint.id == endpoint_id, Endpoint.organization_id == user.organization_id,
        ).with_for_update())
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        if endpoint.status != "approved" or endpoint.os_family != "windows":
            raise HTTPException(status_code=409, detail="Scan requires an approved Windows endpoint")

        job = session.scalar(select(ScanJob).where(
            ScanJob.endpoint_id == endpoint_id,
            ScanJob.organization_id == user.organization_id,
            ScanJob.status.not_in(TERMINAL_SCAN_STATUSES),
        ))
        if job is not None:
            response.status_code = 200
            return summarize_scan_job(job)

        job = ScanJob(organization_id=user.organization_id, endpoint_id=endpoint_id,
                      requested_by=user.user_id, scan_type="persistence_full_scan")
        session.add(job)
        session.flush()
        result = summarize_scan_job(job)
        commit_audit_event(session, user, "scan_jobs.queue", 201, target_id=job.id)
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from error
    return result


ScanJobStatus = Literal[
    "queued", "dispatched", "acknowledged", "running", "uploading", "analyzing", "completed", "partial", "failed", "canceled"
]


@app.get("/api/scan-jobs", tags=["Scans"])
def list_scan_jobs(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    status: ScanJobStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> list[ScanJobSummary]:
    statement = select(ScanJob).options(load_only(
        ScanJob.id, ScanJob.organization_id, ScanJob.endpoint_id, ScanJob.scan_type, ScanJob.status, ScanJob.created_at,
    )).where(ScanJob.organization_id == user.organization_id)
    if status is not None:
        statement = statement.where(ScanJob.status == status)
    statement = statement.order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(limit).offset(offset)
    response.headers["Cache-Control"] = "no-store"
    return [summarize_scan_job(job) for job in session.scalars(statement)]


@app.post("/api/scan-jobs/{job_id}/cancel", tags=["Scans"])
def cancel_scan_job(
    job_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScanJobSummary:
    action = "scan_jobs.cancel"
    if not user.organization_active or user.role not in {"admin", "analyst"}:
        commit_audit_event(session, user, action, 403)
        raise HTTPException(status_code=403, detail="Scan cancellation requires an active admin or analyst account")

    scope = (ScanJob.id == job_id, ScanJob.organization_id == user.organization_id)
    response.headers["Cache-Control"] = "no-store"
    try:
        job = session.scalar(update(ScanJob).where(*scope, ScanJob.status == "queued")
                             .values(status="canceled", finished_at=func.statement_timestamp()).returning(ScanJob))
        if job is not None:
            result = summarize_scan_job(job)
            commit_audit_event(session, user, action, 200, target_id=job.id)
            return result

        job = session.scalar(select(ScanJob).where(*scope))
        if job is None:
            raise HTTPException(status_code=404, detail="Scan job not found")
        if job.status != "canceled":
            raise HTTPException(status_code=409, detail="Only queued scan jobs can be canceled")
        return summarize_scan_job(job)
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from error


@app.get("/api/scan-jobs/{job_id}", tags=["Scans"])
def get_scan_job(
    job_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScanJobSummary:
    job = session.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.organization_id == user.organization_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    response.headers["Cache-Control"] = "no-store"
    return summarize_scan_job(job)


def owned_scan_result(
    job_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScanJob:
    job = session.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.organization_id == user.organization_id))
    if job is None or job.result is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    response.headers["Cache-Control"] = "no-store"
    return job


@app.get("/api/scan-jobs/{job_id}/result", tags=["Scans"])
def get_scan_result(job: Annotated[ScanJob, Depends(owned_scan_result)]) -> dict:
    return {"id": job.id, "status": job.status, "finished_at": job.finished_at, "inventory": job.result}


def assessment_settings(organization_id: UUID, session: Session) -> tuple[tuple[CustomRule, ...], frozenset[tuple[str, str]]]:
    rules = tuple(matching_rule(rule) for rule in session.scalars(select(PublishedDetectionRule).join(
        DetectionRule, (DetectionRule.id == PublishedDetectionRule.rule_id) &
        (DetectionRule.published_version == PublishedDetectionRule.version),
    ).where(DetectionRule.organization_id == organization_id, DetectionRule.enabled.is_(True))
      .order_by(PublishedDetectionRule.name, DetectionRule.id)))
    indicator_rows = session.execute(select(Indicator.kind, Indicator.value).where(
        Indicator.organization_id == organization_id,
    ))
    indicators = build_ioc_index((kind, value) for kind, value in indicator_rows)
    return rules, indicators


def scan_assessment(job: ScanJob, session: Session,
                    settings: tuple[tuple[CustomRule, ...], frozenset[tuple[str, str]]] | None = None) -> dict:
    baseline = None
    if job.finished_at is not None:
        baseline = session.execute(select(ScanJob.id, ScanJob.result).where(
            ScanJob.endpoint_id == job.endpoint_id,
            ScanJob.organization_id == job.organization_id,
            ScanJob.status.in_(("completed", "partial")),
            ScanJob.result.is_not(None),
            ScanJob.finished_at < job.finished_at,
        ).order_by(ScanJob.finished_at.desc(), ScanJob.id.desc()).limit(1)).one_or_none()

    rules, indicators = settings if settings is not None else assessment_settings(job.organization_id, session)
    return {"id": job.id, "scan_status": job.status, "baseline_job_id": baseline.id if baseline else None,
            **assess_scan_report(job.result, str(job.endpoint_id), baseline.result if baseline else None, rules, indicators)}


def finding_evidence(finding: dict, assessment: dict) -> dict:
    baseline = assessment["baseline_job_id"]
    return {**finding, "endpoint_id": assessment["endpoint_id"], "baseline_job_id": str(baseline) if baseline else None}


def finding_fingerprint(evidence: dict, source: str) -> str:
    payload = json.dumps({"source": source, "evidence": evidence}, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def scored_findings(assessment: dict) -> Iterable[tuple[str, dict]]:
    for source, collector in assessment["collectors"].items():
        for finding in collector["assessments"]:
            if finding["score"] > 0:
                yield source, finding


@app.get("/api/scan-jobs/{job_id}/assessment", tags=["Scans"])
def get_scan_assessment(
    job: Annotated[ScanJob, Depends(owned_scan_result)],
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    assessment = scan_assessment(job, session)
    for source, finding in scored_findings(assessment):
        finding["fingerprint"] = finding_fingerprint(finding_evidence(finding, assessment), source)
    return assessment


SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_SOURCES = {"registry": "Registry", "scheduled_tasks": "Scheduled Tasks", "services": "Windows Services"}
FINDINGS_SCAN_BATCH = 5
FINDINGS_PAGE_SIZE = 25


@app.get("/api/findings", tags=["Scans"])
def list_findings(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    query: Annotated[str, Query(max_length=250)] = "",
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    scan_offset: Annotated[int, Query(ge=0, le=2_147_483_640)] = 0,
    offset: Annotated[int, Query(ge=0, le=2_147_483_640)] = 0,
) -> dict:
    scope = ScanJob.organization_id == user.organization_id
    scans = list(session.execute(select(ScanJob, Endpoint.hostname).join(
        Endpoint, (Endpoint.id == ScanJob.endpoint_id) & (Endpoint.organization_id == ScanJob.organization_id),
    ).where(scope, ScanJob.result.is_not(None))
      .options(load_only(ScanJob.id, ScanJob.organization_id, ScanJob.endpoint_id, ScanJob.status, ScanJob.finished_at, ScanJob.created_at))
      .order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).offset(scan_offset).limit(FINDINGS_SCAN_BATCH + 1)))
    batch = scans[:FINDINGS_SCAN_BATCH]
    counts = dict.fromkeys(SEVERITIES, 0)
    terms = query.casefold().split()
    matched = []
    if batch:
        settings = assessment_settings(user.organization_id, session)
        for job, hostname in batch:
            assessment = scan_assessment(job, session, settings)
            for source, finding in scored_findings(assessment):
                attack_id = finding.get("attack_technique", "")
                haystack = " ".join((finding["path"], hostname, str(job.id), FINDING_SOURCES[source], attack_id,
                                     *finding["reasons"])).casefold()
                if terms and not all(term in haystack for term in terms):
                    continue
                counts[finding["severity"]] += 1
                if severity is None or finding["severity"] == severity:
                    matched.append((job.id, job.created_at, hostname, source, finding_evidence(finding, assessment)))
            # Load one raw scan at a time. Finding rows retain only the assessment evidence.
            session.expire(job, ["result"])
    matched.sort(key=lambda row: row[4]["score"], reverse=True)
    response.headers["Cache-Control"] = "no-store"
    return {"can_manage": user.role in {"admin", "analyst"}, "counts": counts, "scan_count": len(batch),
            "has_older_scans": len(scans) > FINDINGS_SCAN_BATCH, "scan_batch_size": FINDINGS_SCAN_BATCH,
            "page_size": FINDINGS_PAGE_SIZE, "total": len(matched),
            "findings": [{**evidence, "scan_job_id": job_id, "scan_created_at": created, "hostname": hostname,
                          "source": source, "fingerprint": finding_fingerprint(evidence, source)}
                         for job_id, created, hostname, source, evidence in matched[offset:offset + FINDINGS_PAGE_SIZE]]}


class CaseFindingLink(BaseModel):
    scan_job_id: UUID
    source: Source
    artifact_index: Annotated[int, Field(ge=0, le=2_147_483_647, strict=True)]
    fingerprint: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


@dataclass(frozen=True)
class CaseFindingSummary:
    id: UUID
    scan_job_id: UUID
    source: Source
    artifact_index: int
    evidence: dict
    attached_at: datetime


def summarize_case_finding(row: CaseFinding) -> CaseFindingSummary:
    return CaseFindingSummary(row.id, row.scan_job_id, row.source, row.artifact_index, row.evidence, row.attached_at)


def owned_case_id(case_id: UUID, user: AuthenticatedUser, session: Session) -> UUID:
    owned = session.scalar(select(CaseRecord.id).where(CaseRecord.id == case_id,
                                                       CaseRecord.organization_id == user.organization_id))
    if owned is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return owned


@app.get("/api/workspace/cases/{case_id}/findings", tags=["Workspace"])
def list_case_findings(
    case_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> list[CaseFindingSummary]:
    owned = owned_case_id(case_id, user, session)
    statement = select(CaseFinding).where(CaseFinding.case_id == owned, CaseFinding.organization_id == user.organization_id)
    response.headers["Cache-Control"] = "no-store"
    return [summarize_case_finding(row) for row in session.scalars(
        statement.order_by(CaseFinding.attached_at.desc(), CaseFinding.id.desc()).offset(offset).limit(WORKSPACE_PAGE_SIZE))]


@app.post("/api/workspace/cases/{case_id}/findings", tags=["Workspace"], status_code=201,
          responses={200: {"model": CaseFindingSummary, "description": "Existing evidence link"}})
def attach_case_finding(
    case_id: UUID, data: CaseFindingLink,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> CaseFindingSummary:
    action = "cases.findings.attach"
    authorize_workspace_write(session, user, action)
    owned_case_id(case_id, user, session)
    scope = select(CaseFinding).where(CaseFinding.organization_id == user.organization_id, CaseFinding.case_id == case_id,
                                      CaseFinding.scan_job_id == data.scan_job_id, CaseFinding.source == data.source,
                                      CaseFinding.artifact_index == data.artifact_index)
    response.headers["Cache-Control"] = "no-store"

    existing = session.scalar(scope)
    if existing is None:
        # The submitted index locates evidence in the server assessment. The browser supplies no evidence values.
        job = owned_scan_result(data.scan_job_id, user, session, response)
        assessment = scan_assessment(job, session)
        findings = assessment["collectors"][data.source]["assessments"]
        row = next((item for item in findings if item["artifact_index"] == data.artifact_index and item["score"] > 0), None)
        if row is None:
            raise HTTPException(status_code=404, detail="Scored finding not found. Refresh the scan assessment.")
        evidence = finding_evidence(row, assessment)
        if finding_fingerprint(evidence, data.source) != data.fingerprint:
            raise HTTPException(status_code=409, detail="This finding changed. Refresh the scan assessment before attaching it.")
        statement = pg_insert(CaseFinding).values(
            organization_id=user.organization_id, case_id=case_id, scan_job_id=job.id,
            source=data.source, artifact_index=data.artifact_index, evidence=evidence,
        ).on_conflict_do_nothing(constraint="uq_case_findings_artifact").returning(CaseFinding)
        linked = session.scalar(statement)
        if linked is not None:
            result = summarize_case_finding(linked)
            commit_audit_event(session, user, action, 201, target_id=case_id)
            return result
        existing = session.scalars(scope).one()

    if finding_fingerprint(existing.evidence, existing.source) != data.fingerprint:
        raise HTTPException(status_code=409, detail="This case already contains an earlier snapshot of the finding.")
    response.status_code = 200
    return summarize_case_finding(existing)
