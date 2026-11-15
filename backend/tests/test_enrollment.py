import os
import unittest
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from textwrap import fill
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, func, select, update
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.enrollment import consume_enrollment_token, issue_enrollment_token
from persistguard.models import Endpoint, EnrollmentToken, Organization


TEST_DATABASE_URL = os.getenv("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class EnrollmentTokenTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(self.engine.dispose)
        self.organization_id, self.other_id = uuid4(), uuid4()
        self.addCleanup(self.remove_test_organizations)
        with Session(self.engine) as session, session.begin():
            session.add_all([
                Organization(id=self.organization_id, name="Enrollment token test"),
                Organization(id=self.other_id, name="Other enrollment organization"),
            ])

    def remove_test_organizations(self):
        ids = [self.organization_id, self.other_id]
        with self.engine.begin() as connection:
            connection.execute(delete(Endpoint).where(Endpoint.organization_id.in_(ids)))
            connection.execute(delete(EnrollmentToken).where(EnrollmentToken.organization_id.in_(ids)))
            connection.execute(delete(Organization).where(Organization.id.in_(ids)))

    def issue_token(self):
        with Session(self.engine) as session, session.begin():
            return issue_enrollment_token(session, self.organization_id)

    def test_token_is_hashed_scoped_and_single_use(self):
        token = self.issue_token()
        digest = sha256(token.encode("ascii")).digest()
        with Session(self.engine) as session, session.begin():
            stored = session.get(EnrollmentToken, digest)
            self.assertEqual(stored.organization_id, self.organization_id)
            self.assertEqual(stored.expires_at - stored.created_at, timedelta(minutes=15))
            self.assertIsNone(stored.used_at)
            self.assertFalse(consume_enrollment_token(session, self.organization_id, "invalid"))
            self.assertFalse(consume_enrollment_token(session, self.other_id, token))
            self.assertTrue(consume_enrollment_token(session, self.organization_id, token))

        with Session(self.engine) as session, session.begin():
            self.assertFalse(consume_enrollment_token(session, self.organization_id, token))
            self.assertIsNotNone(session.get(EnrollmentToken, digest).used_at)

    def test_expired_token_is_rejected_without_being_marked_used(self):
        token = self.issue_token()
        digest = sha256(token.encode("ascii")).digest()
        with Session(self.engine) as session, session.begin():
            session.execute(update(EnrollmentToken).where(EnrollmentToken.token_hash == digest).values(
                created_at=func.now() - timedelta(minutes=16),
                expires_at=func.now() - timedelta(minutes=1),
            ))
            self.assertFalse(consume_enrollment_token(session, self.organization_id, token))
            self.assertIsNone(session.get(EnrollmentToken, digest).used_at)

    def test_rollback_leaves_token_available(self):
        token = self.issue_token()
        with Session(self.engine) as session:
            self.assertTrue(consume_enrollment_token(session, self.organization_id, token))
            session.rollback()

        with Session(self.engine) as session, session.begin():
            self.assertTrue(consume_enrollment_token(session, self.organization_id, token))

    def test_inactive_organization_cannot_issue_or_consume_tokens(self):
        token = self.issue_token()
        with Session(self.engine) as session, session.begin():
            session.get(Organization, self.organization_id).status = "disabled"

        with Session(self.engine) as session, session.begin():
            with self.assertRaisesRegex(ValueError, "active organization"):
                issue_enrollment_token(session, self.organization_id)
            self.assertFalse(consume_enrollment_token(session, self.organization_id, token))

    def test_concurrent_claims_have_only_one_winner(self):
        token = self.issue_token()
        ready = Barrier(2, timeout=5)

        def claim():
            with Session(self.engine) as session, session.begin():
                session.connection()
                ready.wait()
                return consume_enrollment_token(session, self.organization_id, token)

        with ThreadPoolExecutor(max_workers=2) as workers:
            attempts = [workers.submit(claim) for _ in range(2)]
            self.assertCountEqual([attempt.result(timeout=10) for attempt in attempts], [True, False])

    def test_device_registration_validates_csr_and_consumes_token_atomically(self):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
        csr = builder.sign(key, hashes.SHA256())
        tampered = bytearray(csr.public_bytes(Encoding.DER))
        tampered[-1] ^= 1
        invalid_csr = (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + fill(b64encode(tampered).decode("ascii"), width=64)
            + "\n-----END CERTIFICATE REQUEST-----\n"
        )
        self.assertFalse(x509.load_pem_x509_csr(invalid_csr.encode("ascii")).is_signature_valid)
        wrong_curve = builder.sign(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384())
        token = self.issue_token()
        headers = {"Authorization": f"Bearer {token}"}
        route = "/api/agent/enroll"
        payload = {
            "organization_id": str(self.organization_id),
            "hostname": "test-agent",
            "os_family": "windows",
            "agent_version": "0.1.0",
            "csr": csr.public_bytes(Encoding.PEM).decode("ascii"),
        }

        with patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}), TestClient(app) as client:
            self.assertEqual(client.post(route, json=payload).status_code, 401)
            other_payload = {**payload, "organization_id": str(self.other_id)}
            self.assertEqual(client.post(route, json=other_payload, headers=headers).status_code, 401)

            for bad_csr in ("not PEM", invalid_csr, wrong_curve.public_bytes(Encoding.PEM).decode("ascii")):
                response = client.post(route, json={**payload, "csr": bad_csr}, headers=headers)
                self.assertEqual(response.status_code, 422)

            response = client.post(route, json=payload, headers=headers)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            registration = response.json()
            self.assertEqual(registration["status"], "pending")
            self.assertEqual(client.post(route, json=payload, headers=headers).status_code, 401)

            second_token = self.issue_token()
            second_headers = {"Authorization": f"Bearer {second_token}"}
            self.assertEqual(client.post(route, json=payload, headers=second_headers).status_code, 409)
            new_key = ec.generate_private_key(ec.SECP256R1())
            new_csr = builder.sign(new_key, hashes.SHA256()).public_bytes(Encoding.PEM).decode("ascii")
            response = client.post(route, json={**payload, "csr": new_csr}, headers=second_headers)
            self.assertEqual(response.status_code, 201)

        with Session(self.engine) as session:
            endpoints = session.scalars(select(Endpoint).where(
                Endpoint.organization_id.in_([self.organization_id, self.other_id])
            )).all()
            self.assertEqual(len(endpoints), 2)
            stored = next(endpoint for endpoint in endpoints if str(endpoint.id) == registration["endpoint_id"])
            self.assertEqual(stored.organization_id, self.organization_id)
            self.assertEqual(stored.hostname, "test-agent")
            self.assertEqual(stored.agent_version, "0.1.0")
            self.assertEqual(stored.status, "pending")
            self.assertEqual(stored.device_public_key, key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ))
