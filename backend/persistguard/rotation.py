import os
import re
from datetime import datetime, timezone
from hmac import compare_digest
from typing import Annotated, Literal
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import insert, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from persistguard.auth import database_session
from persistguard.client_certificates import CertificateIssuanceError, issue_client_certificate
from persistguard.models import AgentCredential, AuditEvent, Endpoint, Organization


router = APIRouter(include_in_schema=False)


class GatewayCredential(BaseModel):
    endpoint_id: UUID
    certificate_serial: Annotated[str, Field(pattern=r"^[1-9a-f][0-9a-f]{0,39}$")]
    certificate_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def require_gateway(authorization: Annotated[str | None, Header()] = None) -> None:
    secret = os.getenv("PERSISTGUARD_ROTATION_SECRET", "")
    if not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise HTTPException(status_code=503, detail="Certificate rotation is unavailable")
    if not compare_digest((authorization or "").encode(), ("Bearer " + secret).encode()):
        raise HTTPException(status_code=401, detail="Gateway authentication required")


def record_rotation(session: Session, endpoint: Endpoint, action: str) -> None:
    session.execute(insert(AuditEvent.__table__).inline().values(
        organization_id=endpoint.organization_id,
        actor_id=endpoint.id,
        target_id=endpoint.id,
        action=action,
        status_code=200,
    ))


def renew_certificate(
    session: Session, endpoint: Endpoint, current: AgentCredential, now: datetime
) -> AgentCredential:
    successor = session.scalar(select(AgentCredential).where(
        AgentCredential.replaces_serial == current.certificate_serial,
        AgentCredential.endpoint_id == endpoint.id,
    ))
    if successor is not None:
        if successor.revoked_at is not None or successor.expires_at <= now or successor.superseded_at is not None:
            raise HTTPException(status_code=409, detail="Replacement certificate is no longer available")
        return successor

    if current.replaces_serial:
        previous = session.get(AgentCredential, current.replaces_serial)
        if previous and previous.revoked_at is None and previous.expires_at > now:
            return current

    certificate = issue_client_certificate(endpoint.id, endpoint.device_public_key)
    if certificate.not_valid_after_utc <= current.expires_at:
        raise HTTPException(status_code=409, detail="Replacement would not extend certificate validity")
    current.superseded_at = now
    session.flush()
    successor = AgentCredential(
        certificate_serial=format(certificate.serial_number, "x"),
        endpoint_id=endpoint.id,
        certificate_pem=certificate.public_bytes(Encoding.PEM).decode("ascii"),
        expires_at=certificate.not_valid_after_utc,
        replaces_serial=current.certificate_serial,
    )
    session.add(successor)
    record_rotation(session, endpoint, "agent_credentials.renew")
    return successor


@router.post("/internal/agent/certificate/{operation}", dependencies=[Depends(require_gateway)])
def rotate_certificate(
    operation: Literal["renew", "confirm"],
    proof: GatewayCredential,
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    denied = HTTPException(status_code=403, detail="Device credential unavailable")
    try:
        # Serialize approval and rotation for this endpoint, then read the current credential state.
        endpoint = session.scalar(select(Endpoint).join(Organization, Organization.id == Endpoint.organization_id).where(
            Endpoint.id == proof.endpoint_id, Endpoint.status == "approved", Organization.status == "active",
        ).with_for_update(of=Endpoint))
        if endpoint is None or endpoint.device_public_key is None:
            raise denied
        now = datetime.now(timezone.utc)
        current = session.get(AgentCredential, proof.certificate_serial)
        if current is None or current.endpoint_id != endpoint.id or current.revoked_at or current.expires_at <= now:
            raise denied
        existing = x509.load_pem_x509_certificate(current.certificate_pem.encode("ascii"))
        if not compare_digest(existing.fingerprint(hashes.SHA256()).hex(), proof.certificate_sha256):
            raise denied
        if existing.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != endpoint.device_public_key:
            raise denied

        if operation == "renew":
            replacement = renew_certificate(session, endpoint, current, now)
            result = {"certificate_pem": replacement.certificate_pem, "expires_at": replacement.expires_at}
        else:
            if not current.replaces_serial or current.superseded_at is not None:
                raise HTTPException(status_code=409, detail="Device must present its replacement certificate")
            previous = session.get(AgentCredential, current.replaces_serial)
            if previous is None or previous.endpoint_id != endpoint.id:
                raise denied
            if previous.revoked_at is None:
                previous.revoked_at = now
                record_rotation(session, endpoint, "agent_credentials.confirm")
            result = {"confirmed": True}

        session.commit()
        return result
    except (CertificateIssuanceError, SQLAlchemyError, ValueError) as error:
        raise HTTPException(status_code=503, detail="Certificate rotation is unavailable") from error
