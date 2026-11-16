from typing import Literal
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, load_only

from persistguard.models import Endpoint, ScanJob
from persistguard.normalize_inventory import Source


TERMINAL_SCAN_STATUSES = ("completed", "partial", "failed", "canceled")
FULL_SCAN_TYPE = "persistence_full_scan"
TARGETED_SCAN_SOURCES: dict[str, Source] = {
    "persistence_registry_scan": "registry",
    "persistence_scheduled_tasks_scan": "scheduled_tasks",
    "persistence_services_scan": "services",
}
SCAN_JOB_SUMMARY_COLUMNS = load_only(ScanJob.id, ScanJob.organization_id, ScanJob.endpoint_id, ScanJob.scan_type,
                                     ScanJob.status, ScanJob.created_at, ScanJob.schedule_id)


class ScanRequest(BaseModel):
    scan_type: Literal["persistence_full_scan", "persistence_registry_scan", "persistence_scheduled_tasks_scan",
                       "persistence_services_scan"] = FULL_SCAN_TYPE


def lock_scan_endpoint(session: Session, organization_id: UUID, endpoint_id: UUID) -> Endpoint | None:
    return session.scalar(select(Endpoint).where(Endpoint.id == endpoint_id,
                          Endpoint.organization_id == organization_id).with_for_update())


def eligible_scan_endpoint(endpoint: Endpoint | None) -> bool:
    return endpoint is not None and endpoint.status == "approved" and endpoint.os_family == "windows"


def open_scan_job(session: Session, organization_id: UUID, endpoint_id: UUID) -> ScanJob | None:
    return session.scalar(select(ScanJob).options(SCAN_JOB_SUMMARY_COLUMNS).where(
        ScanJob.endpoint_id == endpoint_id, ScanJob.organization_id == organization_id,
        ScanJob.status.not_in(TERMINAL_SCAN_STATUSES),
    ))
