import re
from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from persistguard.models import EnrollmentToken, Organization


TOKEN_LIFETIME = timedelta(minutes=15)
TOKEN_FORMAT = re.compile(r"[a-zA-Z0-9_-]{43}")


def issue_enrollment_token(session: Session, organization_id: UUID) -> str:
    """Issue a token for an authorized caller to return after committing."""
    active_organization = session.scalar(
        select(Organization.id).where(Organization.id == organization_id, Organization.status == "active")
    )
    if active_organization is None:
        raise ValueError("Enrollment requires an active organization")

    token = token_urlsafe(32)
    session.add(EnrollmentToken(
        token_hash=sha256(token.encode("ascii")).digest(),
        organization_id=organization_id,
        expires_at=func.statement_timestamp() + TOKEN_LIFETIME,
    ))
    session.flush()
    return token


def consume_enrollment_token(session: Session, organization_id: UUID, token: str) -> bool:
    """Claim a token inside the same transaction as endpoint enrollment."""
    if not TOKEN_FORMAT.fullmatch(token):
        return False

    active_organization = select(Organization.id).where(
        Organization.id == organization_id, Organization.status == "active"
    ).exists()
    claimed = session.scalar(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == sha256(token.encode("ascii")).digest(),
            EnrollmentToken.organization_id == organization_id,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > func.clock_timestamp(),
            active_organization,
        )
        .values(used_at=func.clock_timestamp())
        .returning(EnrollmentToken.token_hash)
    )
    return claimed is not None
