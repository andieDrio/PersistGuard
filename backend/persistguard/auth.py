import os
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from uuid import UUID

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.exc import ArgumentError, OperationalError
from sqlalchemy.orm import Session

from persistguard.models import Organization, User


bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str


@dataclass(frozen=True)
class LocalIdentity:
    subject: str
    user_id: UUID
    organization_id: UUID


@dataclass(frozen=True)
class AuthenticatedUser(LocalIdentity):
    role: str
    organization_active: bool


def verified_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> VerifiedIdentity:
    unauthorized = HTTPException(
        status_code=401,
        detail="Valid bearer token required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    issuer = os.getenv("PERSISTGUARD_AUTH_ISSUER")
    audience = os.getenv("PERSISTGUARD_AUTH_AUDIENCE")
    key_file = os.getenv("PERSISTGUARD_AUTH_PUBLIC_KEY_FILE")
    unavailable = HTTPException(status_code=503, detail="Authentication unavailable")
    if not issuer or not audience or not key_file:
        raise unavailable

    try:
        key = load_pem_public_key(Path(key_file).read_bytes())
    except (OSError, ValueError, UnsupportedAlgorithm) as error:
        raise unavailable from error
    if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
        raise unavailable

    try:
        claims = jwt.decode(
            credentials.credentials,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except (jwt.InvalidTokenError, TypeError, OverflowError) as error:
        raise unauthorized from error

    subject = claims["sub"]
    if not isinstance(subject, str) or not subject.strip() or "\x00" in subject:
        raise unauthorized
    try:
        subject.encode("utf-8")
    except UnicodeError as error:
        raise unauthorized from error
    return VerifiedIdentity(issuer=issuer, subject=subject)


@lru_cache(maxsize=1)
def identity_engine(database_url: str) -> Engine:
    return create_engine(database_url, pool_pre_ping=True)


def database_session() -> Iterator[Session]:
    database_url = os.getenv("PERSISTGUARD_DATABASE_URL")
    unavailable = HTTPException(status_code=503, detail="Identity database unavailable")
    if not database_url:
        raise unavailable

    try:
        with Session(identity_engine(database_url)) as session:
            yield session
    except (ArgumentError, OperationalError) as error:
        raise unavailable from error


def linked_account(
    identity: Annotated[VerifiedIdentity, Depends(verified_identity)],
    session: Annotated[Session, Depends(database_session)],
) -> AuthenticatedUser:
    statement = (
        select(User.id, User.organization_id, User.role, Organization.status)
        .join(User.organization)
        .where(
            User.identity_issuer == identity.issuer,
            User.identity_subject == identity.subject,
        )
    )
    account = session.execute(statement).one_or_none()
    if account is None:
        raise HTTPException(status_code=403, detail="No active local account")
    return AuthenticatedUser(
        identity.subject, account.id, account.organization_id, account.role, account.status == "active"
    )


def local_identity(user: Annotated[AuthenticatedUser, Depends(linked_account)]) -> AuthenticatedUser:
    if not user.organization_active:
        raise HTTPException(status_code=403, detail="No active local account")
    return user
