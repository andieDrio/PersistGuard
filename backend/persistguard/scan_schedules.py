import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response
from pydantic import AwareDatetime, BaseModel, StrictBool
from sqlalchemy import Engine, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from persistguard.audit import commit_audit_event
from persistguard.auth import AuthenticatedUser, database_session, identity_engine, linked_account, local_identity
from persistguard.models import AuditEvent, Endpoint, Organization, ScanJob, ScanSchedule, ScanScheduleRun, User
from persistguard.scan_queue import ScanRequest, eligible_scan_endpoint, lock_scan_endpoint, open_scan_job


router = APIRouter(prefix="/api/scan-schedules", tags=["Scans"])
logger = logging.getLogger(__name__)
Frequency = Literal["daily", "weekly"]
INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
MANAGERS = ("admin", "analyst")


class ScheduleTiming(BaseModel):
    frequency: Frequency
    next_run_at: AwareDatetime


class CreateSchedule(ScanRequest, ScheduleTiming):
    endpoint_id: UUID


class UpdateSchedule(BaseModel):
    enabled: StrictBool | None = None
    timing: ScheduleTiming | None = None


@dataclass(frozen=True)
class ScheduleSummary:
    id: UUID
    endpoint_id: UUID
    hostname: str
    scan_type: str
    frequency: str
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_outcome: str | None


@dataclass(frozen=True)
class SchedulePage:
    schedules: list[ScheduleSummary]
    has_more: bool


@dataclass(frozen=True)
class ScheduleRunSummary:
    id: UUID
    scheduled_for: datetime | None
    attempted_at: datetime
    outcome: str
    job_id: UUID | None
    job_status: str | None


@dataclass(frozen=True)
class ScheduleRunPage:
    schedule: ScheduleSummary
    runs: list[ScheduleRunSummary]
    has_more: bool


def summarize(schedule: ScanSchedule, hostname: str) -> ScheduleSummary:
    return ScheduleSummary(schedule.id, schedule.endpoint_id, hostname, schedule.scan_type, schedule.frequency,
                           schedule.enabled, schedule.next_run_at, schedule.last_run_at, schedule.last_outcome)


def tenant_schedules(organization_id: UUID):
    return select(ScanSchedule, Endpoint.hostname).join(
        Endpoint, (Endpoint.id == ScanSchedule.endpoint_id) & (Endpoint.organization_id == ScanSchedule.organization_id),
    ).where(ScanSchedule.organization_id == organization_id)


def require_manager(session: Session, user: AuthenticatedUser, action: str) -> None:
    if not user.organization_active or user.role not in MANAGERS:
        commit_audit_event(session, user, action, 403)
        raise HTTPException(status_code=403, detail="Recurring scans require an active admin or analyst account")


def validate_start(next_run_at: datetime, now: datetime) -> None:
    if next_run_at <= now:
        raise HTTPException(status_code=422, detail="Choose a first run in the future")


def next_occurrence(scheduled_for: datetime, frequency: str, now: datetime) -> datetime:
    due = scheduled_for.astimezone(timezone.utc)
    if due > now:
        return due
    interval = INTERVALS[frequency]
    return due + ((now.astimezone(timezone.utc) - due) // interval + 1) * interval


@router.get("")
def list_schedules(
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> SchedulePage:
    statement = tenant_schedules(user.organization_id).order_by(
        Endpoint.hostname, ScanSchedule.scan_type, ScanSchedule.id,
    ).limit(limit + 1).offset(offset)
    rows = session.execute(statement).all()
    response.headers["Cache-Control"] = "no-store"
    return SchedulePage([summarize(schedule, hostname) for schedule, hostname in rows[:limit]], len(rows) > limit)


@router.get("/{schedule_id}/runs")
def list_schedule_runs(
    schedule_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(local_identity)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=2_147_483_647)] = 0,
) -> ScheduleRunPage:
    target = session.execute(tenant_schedules(user.organization_id).where(ScanSchedule.id == schedule_id)).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found")
    statement = select(ScanScheduleRun, ScanJob.id, ScanJob.status).outerjoin(ScanJob, (
        (ScanJob.id == ScanScheduleRun.job_id) & (ScanJob.organization_id == ScanScheduleRun.organization_id) &
        (ScanJob.schedule_id == ScanScheduleRun.schedule_id)
    )).where(
        ScanScheduleRun.schedule_id == schedule_id, ScanScheduleRun.organization_id == user.organization_id,
    ).order_by(ScanScheduleRun.attempted_at.desc(), ScanScheduleRun.id.desc()).limit(limit + 1).offset(offset)
    rows = session.execute(statement).all()
    response.headers["Cache-Control"] = "no-store"
    return ScheduleRunPage(summarize(*target), [
        ScheduleRunSummary(run.id, run.scheduled_for, run.attempted_at, run.outcome, job_id, status)
        for run, job_id, status in rows[:limit]
    ], len(rows) > limit)


@router.post("", status_code=201)
def create_schedule(
    data: CreateSchedule,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScheduleSummary:
    action = "scan_schedules.create"
    require_manager(session, user, action)
    endpoint = session.scalar(select(Endpoint).where(Endpoint.id == data.endpoint_id,
                              Endpoint.organization_id == user.organization_id))
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if not eligible_scan_endpoint(endpoint):
        raise HTTPException(status_code=409, detail="Choose an approved Windows endpoint")
    validate_start(data.next_run_at, session.scalar(select(func.statement_timestamp())))
    schedule = session.scalar(insert(ScanSchedule).values(
        organization_id=user.organization_id, requested_by=user.user_id, **data.model_dump(),
    ).on_conflict_do_nothing(constraint="uq_scan_schedules_endpoint_scope").returning(ScanSchedule))
    if schedule is None:
        raise HTTPException(status_code=409, detail="This endpoint already has a schedule for this scope. Edit the existing schedule.")
    result = summarize(schedule, endpoint.hostname)
    commit_audit_event(session, user, action, 201, target_id=schedule.id)
    response.headers["Cache-Control"] = "no-store"
    return result


@router.patch("/{schedule_id}")
def update_schedule(
    schedule_id: UUID,
    data: UpdateSchedule,
    user: Annotated[AuthenticatedUser, Depends(linked_account)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> ScheduleSummary:
    action = "scan_schedules.update"
    require_manager(session, user, action)
    if data.timing is None and data.enabled is None:
        raise HTTPException(status_code=422, detail="Choose a timing or status change")
    schedule = session.scalar(select(ScanSchedule).where(ScanSchedule.id == schedule_id,
                              ScanSchedule.organization_id == user.organization_id).with_for_update())
    if schedule is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found")
    endpoint = lock_scan_endpoint(session, schedule.organization_id, schedule.endpoint_id)
    now = session.scalar(select(func.statement_timestamp()))
    enabled = schedule.enabled if data.enabled is None else data.enabled
    if enabled and not eligible_scan_endpoint(endpoint):
        raise HTTPException(status_code=409, detail="This endpoint is no longer eligible for a scheduled scan")
    if data.timing is not None:
        validate_start(data.timing.next_run_at, now)
        schedule.frequency = data.timing.frequency
        schedule.next_run_at = data.timing.next_run_at
    elif enabled and not schedule.enabled:
        schedule.next_run_at = next_occurrence(schedule.next_run_at, schedule.frequency, now)
    if enabled:
        schedule.requested_by = user.user_id
    schedule.enabled = enabled
    result = summarize(schedule, endpoint.hostname)
    commit_audit_event(session, user, action, 200, target_id=schedule.id)
    response.headers["Cache-Control"] = "no-store"
    return result


def process_due_schedules(engine: Engine, limit: int = 25) -> None:
    for _ in range(limit):
        # Each transaction holds at most one schedule row and one endpoint row.
        with Session(engine) as session, session.begin():
            schedule = session.scalar(select(ScanSchedule).where(
                ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= func.statement_timestamp(),
            ).order_by(ScanSchedule.next_run_at, ScanSchedule.id).limit(1).with_for_update(skip_locked=True))
            if schedule is None:
                return

            endpoint = lock_scan_endpoint(session, schedule.organization_id, schedule.endpoint_id)
            owner = session.scalar(select(User.id).join(User.organization).where(
                User.id == schedule.requested_by, User.organization_id == schedule.organization_id,
                User.role.in_(MANAGERS), User.identity_subject.is_not(None), Organization.status == "active",
            ).with_for_update(read=True, of=(User, Organization)))
            now = session.scalar(select(func.statement_timestamp()))
            scheduled_for = schedule.next_run_at
            job_id = None
            schedule.last_run_at = now
            schedule.next_run_at = next_occurrence(scheduled_for, schedule.frequency, now)
            if owner is None:
                schedule.enabled = False
                schedule.last_outcome = "paused_owner"
            elif not eligible_scan_endpoint(endpoint):
                schedule.enabled = False
                schedule.last_outcome = "paused_endpoint"
            elif open_scan_job(session, schedule.organization_id, schedule.endpoint_id) is not None:
                schedule.last_outcome = "skipped_busy"
            else:
                job = ScanJob(organization_id=schedule.organization_id, endpoint_id=schedule.endpoint_id,
                              requested_by=owner, scan_type=schedule.scan_type, schedule_id=schedule.id)
                session.add(job)
                session.flush()
                job_id = job.id
                session.add(AuditEvent(organization_id=schedule.organization_id, actor_id=owner,
                                       action="scan_jobs.schedule", status_code=201, target_id=job.id))
                schedule.last_outcome = "queued"
            session.add(ScanScheduleRun(organization_id=schedule.organization_id, schedule_id=schedule.id,
                                        job_id=job_id, scheduled_for=scheduled_for, attempted_at=now,
                                        outcome=schedule.last_outcome))


async def run_scheduler(database_url: str, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.to_thread(process_due_schedules, identity_engine(database_url))
        except SQLAlchemyError:
            logger.warning("Recurring scan scheduler could not process the queue")
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except TimeoutError:
            pass


@asynccontextmanager
async def scheduler_lifespan(app: FastAPI):
    database_url = os.getenv("PERSISTGUARD_DATABASE_URL")
    if not database_url:
        yield
        return

    stop = asyncio.Event()
    task = asyncio.create_task(run_scheduler(database_url, stop))
    try:
        yield
    finally:
        stop.set()
        await task
