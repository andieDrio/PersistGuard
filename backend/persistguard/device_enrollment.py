from typing import Annotated, Literal
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from persistguard.auth import bearer, database_session
from persistguard.enrollment import consume_enrollment_token
from persistguard.models import Endpoint


router = APIRouter(tags=["Enrollment"])


class DeviceEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253,
                                               pattern=r"^[^\x00-\x1f\x7f]+$")]
    os_family: Literal["windows", "linux", "macos"]
    agent_version: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64,
                                                    pattern=r"^[^\x00-\x1f\x7f]+$")] | None = None
    csr: Annotated[str, StringConstraints(max_length=4096)]


class DeviceEnrollmentResponse(BaseModel):
    endpoint_id: UUID
    status: Literal["pending"]


def verified_public_key(pem: str) -> bytes:
    try:
        request = x509.load_pem_x509_csr(pem.encode("ascii"))
        key = request.public_key()
        if (not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)
                or request.signature_algorithm_oid != x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256
                or not request.is_signature_valid):
            raise ValueError("Invalid device CSR")
    except (ValueError, UnsupportedAlgorithm) as error:
        raise HTTPException(status_code=422, detail="A valid ECDSA P-256 CSR is required") from error
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


@router.post("/api/agent/enroll", status_code=201)
def enroll_device(
    request: DeviceEnrollmentRequest,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Annotated[Session, Depends(database_session)],
    response: Response,
) -> DeviceEnrollmentResponse:
    unauthorized = HTTPException(
        status_code=401,
        detail="Valid enrollment token required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    try:
        if not consume_enrollment_token(session, request.organization_id, credentials.credentials):
            raise unauthorized
        endpoint = Endpoint(
            organization_id=request.organization_id,
            hostname=request.hostname,
            os_family=request.os_family,
            agent_version=request.agent_version,
            device_public_key=verified_public_key(request.csr),
        )
        session.add(endpoint)
        session.flush()
        result = DeviceEnrollmentResponse(endpoint_id=endpoint.id, status="pending")
        session.commit()
    except IntegrityError as error:
        diagnostic = getattr(error.orig, "diag", None)
        if getattr(diagnostic, "constraint_name", None) == "uq_endpoints_org_device_key":
            raise HTTPException(status_code=409, detail="Device key is already registered") from error
        raise HTTPException(status_code=503, detail="Device enrollment unavailable") from error
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Device enrollment unavailable") from error

    response.headers["Cache-Control"] = "no-store"
    return result
