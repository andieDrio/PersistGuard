from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from persistguard.auth import AuthenticatedUser
from persistguard.models import AuditEvent


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
