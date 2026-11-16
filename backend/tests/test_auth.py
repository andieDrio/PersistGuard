import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.models import AgentCredential, AuditEvent, Endpoint, EnrollmentToken, Organization, ScanJob, User


TEST_DATABASE_URL = os.getenv("PERSISTGUARD_TEST_DATABASE_URL")


class AuthenticationTests(unittest.TestCase):
    issuer = "https://identity.example.test/"
    audience = "https://persistguard.example.test/api"

    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.public_key_file = Path(directory.name) / "public.pem"
        cls.public_key_file.write_bytes(cls.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    def setUp(self):
        self.enterContext(patch.dict(os.environ, {
            "PERSISTGUARD_AUTH_ISSUER": self.issuer,
            "PERSISTGUARD_AUTH_AUDIENCE": self.audience,
            "PERSISTGUARD_AUTH_PUBLIC_KEY_FILE": str(self.public_key_file),
        }))
        self.client = self.enterContext(TestClient(app))

    def token(self, signing_key=None, **overrides):
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "test-subject",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        claims.update(overrides)
        return jwt.encode(claims, signing_key or self.signing_key, algorithm="RS256")

    @unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
    def test_valid_token_requires_an_exact_link_to_an_active_organization(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        self.enterContext(patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}))
        active_id, inactive_id = uuid4(), uuid4()
        subject = "linked-" + str(uuid4())

        def remove_test_accounts():
            with engine.begin() as connection:
                ids = [active_id, inactive_id]
                connection.execute(delete(User).where(User.organization_id.in_(ids)))
                connection.execute(delete(Organization).where(Organization.id.in_(ids)))

        self.addCleanup(remove_test_accounts)
        with Session(engine) as session, session.begin():
            active = Organization(id=active_id, name="Active identity test")
            inactive = Organization(id=inactive_id, name="Inactive identity test", status="disabled")
            user = User(organization=active, email="linked@example.test", role="viewer",
                        identity_issuer=self.issuer, identity_subject=subject)
            other_issuer = User(organization=active, email="other@example.test", role="viewer",
                                identity_issuer="https://other.example.test/", identity_subject="other-issuer")
            disabled = User(organization=inactive, email="disabled@example.test", role="viewer",
                            identity_issuer=self.issuer, identity_subject="disabled-" + subject)
            session.add_all([user, other_issuer, disabled])
            session.flush()
            user_id = user.id

        response = self.client.get("/api/me", headers={"Authorization": f"Bearer {self.token(sub=subject)}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "subject": subject, "user_id": str(user_id), "organization_id": str(active_id),
        })
        self.assertEqual(response.headers["Cache-Control"], "no-store")

        for unlinked_subject in ("missing-" + subject, subject.upper(), "other-issuer", "disabled-" + subject):
            with self.subTest(subject=unlinked_subject):
                token = self.token(sub=unlinked_subject)
                response = self.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 403)

    def test_valid_token_without_database_configuration(self):
        with patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": ""}):
            response = self.client.get("/api/me", headers={"Authorization": f"Bearer {self.token()}"})
        self.assertEqual(response.status_code, 503)

    @unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
    def test_list_users_checks_database_role_and_organization(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        self.enterContext(patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}))
        organization_id, other_id = uuid4(), uuid4()
        suffix = str(uuid4())

        def remove_test_accounts():
            with engine.begin() as connection:
                ids = [organization_id, other_id]
                connection.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(ids)))
                connection.execute(delete(User).where(User.organization_id.in_(ids)))
                connection.execute(delete(Organization).where(Organization.id.in_(ids)))

        self.addCleanup(remove_test_accounts)
        with Session(engine) as session, session.begin():
            organization = Organization(id=organization_id, name="RBAC test")
            other = Organization(id=other_id, name="Other RBAC organization")
            users = [
                User(
                    organization=organization, email=f"{role}@example.test", role=role,
                    identity_issuer=self.issuer, identity_subject=f"{role}-{suffix}",
                )
                for role in ("admin", "analyst", "viewer")
            ]
            session.add_all(users)
            session.add(User(organization=other, email="outside@example.test", role="admin"))
            session.flush()
            admin_id, analyst_id, viewer_id = [user.id for user in users]
            expected = [
                {"id": str(user.id), "email": user.email, "role": user.role}
                for user in sorted(users, key=lambda user: user.id)
            ]

        self.assertEqual(self.client.get("/api/users").status_code, 401)
        for role in ("analyst", "viewer"):
            with self.subTest(role=role):
                token = self.token(sub=f"{role}-{suffix}", role="admin")
                response = self.client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 403)

        token = self.token(sub=f"admin-{suffix}")
        headers = {"Authorization": f"Bearer {token}"}
        response = self.client.get("/api/users", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/api/users?limit=1&offset=1", headers=headers).json(), expected[1:2])
        self.assertEqual(self.client.get("/api/users?limit=101", headers=headers).status_code, 422)

        with patch.object(Session, "commit", side_effect=SQLAlchemyError("Audit write failed")):
            response = self.client.get("/api/users", headers=headers)
        self.assertEqual(response.status_code, 503)

        with Session(engine) as session, session.begin():
            session.get(User, admin_id).role = "viewer"

        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 403)

        with Session(engine) as session, session.begin():
            session.get(User, admin_id).role = "admin"
            session.get(Organization, organization_id).status = "disabled"

        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 403)

        with Session(engine) as session:
            events = session.scalars(select(AuditEvent).where(
                AuditEvent.organization_id.in_([organization_id, other_id])
            )).all()
            self.assertEqual(
                Counter((event.actor_id, event.status_code) for event in events),
                Counter({(admin_id, 200): 2, (admin_id, 403): 2, (analyst_id, 403): 1, (viewer_id, 403): 1}),
            )
            for event in events:
                self.assertEqual(event.organization_id, organization_id)
                self.assertEqual(event.action, "users.list")
                self.assertIsNotNone(event.occurred_at.tzinfo)

    @unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
    def test_issue_enrollment_token_requires_admin_and_uses_local_organization(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        self.enterContext(patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}))
        organization_id, other_id = uuid4(), uuid4()
        suffix = str(uuid4())

        def remove_test_accounts():
            with engine.begin() as connection:
                ids = [organization_id, other_id]
                connection.execute(delete(EnrollmentToken).where(EnrollmentToken.organization_id.in_(ids)))
                connection.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(ids)))
                connection.execute(delete(User).where(User.organization_id.in_(ids)))
                connection.execute(delete(Organization).where(Organization.id.in_(ids)))

        self.addCleanup(remove_test_accounts)
        with Session(engine) as session, session.begin():
            organization = Organization(id=organization_id, name="Enrollment API test")
            session.add(Organization(id=other_id, name="Other enrollment API organization"))
            users = {
                role: User(
                    organization=organization, email=f"{role}@example.test", role=role,
                    identity_issuer=self.issuer, identity_subject=f"{role}-{suffix}",
                )
                for role in ("admin", "analyst", "viewer")
            }
            session.add_all(users.values())
            session.flush()
            actor_ids = {role: user.id for role, user in users.items()}

        route = "/api/enrollment-tokens"
        self.assertEqual(self.client.post(route).status_code, 401)
        for role in ("analyst", "viewer"):
            with self.subTest(role=role):
                token = self.token(sub=f"{role}-{suffix}", role="admin")
                response = self.client.post(route, headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 403)

        bearer = self.token(sub=f"admin-{suffix}")
        headers = {"Authorization": f"Bearer {bearer}"}
        response = self.client.post(route, headers=headers, params={"organization_id": str(other_id)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        invitation = response.json()
        self.assertEqual(invitation["organization_id"], str(organization_id))
        self.assertEqual(invitation["expires_in_seconds"], 900)
        digest = sha256(invitation["token"].encode("ascii")).digest()

        with patch.object(Session, "commit", side_effect=SQLAlchemyError("Audit write failed")):
            response = self.client.post(route, headers=headers)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("token", response.json())

        with Session(engine) as session:
            ids = [organization_id, other_id]
            tokens = session.scalars(select(EnrollmentToken).where(EnrollmentToken.organization_id.in_(ids))).all()
            self.assertEqual([(token.token_hash, token.organization_id) for token in tokens], [(digest, organization_id)])
            events = session.scalars(select(AuditEvent).where(AuditEvent.organization_id.in_(ids))).all()
            self.assertCountEqual(
                [(event.actor_id, event.status_code, event.organization_id, event.action) for event in events],
                [
                    (actor_ids["admin"], 201, organization_id, "enrollment_tokens.issue"),
                    (actor_ids["analyst"], 403, organization_id, "enrollment_tokens.issue"),
                    (actor_ids["viewer"], 403, organization_id, "enrollment_tokens.issue"),
                ],
            )

    @unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
    def test_admin_issues_and_revokes_client_credentials_for_own_endpoint(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        self.enterContext(patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}))
        organization_id, other_id, endpoint_id, foreign_id = [uuid4() for _ in range(4)]

        def remove_test_accounts():
            with engine.begin() as connection:
                ids = [organization_id, other_id]
                connection.execute(delete(ScanJob).where(ScanJob.organization_id == organization_id))
                connection.execute(delete(AgentCredential).where(AgentCredential.endpoint_id == endpoint_id))
                connection.execute(delete(Endpoint).where(Endpoint.organization_id.in_(ids)))
                connection.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(ids)))
                connection.execute(delete(User).where(User.organization_id.in_(ids)))
                connection.execute(delete(Organization).where(Organization.id.in_(ids)))

        self.addCleanup(remove_test_accounts)
        public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        device_key = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with Session(engine) as session, session.begin():
            organization = Organization(id=organization_id, name="Certificate issue test")
            foreign = Organization(id=other_id, name="Other certificate organization")
            admin = User(organization=organization, email="admin@example.test", role="admin",
                         identity_issuer=self.issuer, identity_subject=f"admin-{endpoint_id}")
            analyst = User(organization=organization, email="analyst@example.test", role="analyst",
                           identity_issuer=self.issuer, identity_subject=f"analyst-{endpoint_id}")
            session.add_all([
                admin, analyst,
                Endpoint(id=endpoint_id, organization=organization, hostname="registered", os_family="windows",
                         device_public_key=device_key),
                Endpoint(id=foreign_id, organization=foreign, hostname="outside", os_family="windows",
                         device_public_key=device_key),
            ])
            session.flush()
            admin_id = admin.id

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PersistGuard test CA")])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
              .sign(ca_key, hashes.SHA256()))
        ca_dir = Path(self.enterContext(TemporaryDirectory()))
        ca_file, key_file = ca_dir / "ca.pem", ca_dir / "ca-key.pem"
        ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))

        route = f"/api/endpoints/{endpoint_id}/client-certificate"
        token = self.token(sub=f"admin-{endpoint_id}")
        headers = {"Authorization": f"Bearer {token}"}
        token = self.token(sub=f"analyst-{endpoint_id}", role="admin")
        self.assertEqual(self.client.put(route, headers={"Authorization": f"Bearer {token}"}).status_code, 403)
        self.assertEqual(self.client.get("/api/endpoints", headers={"Authorization": f"Bearer {token}"}).status_code, 403)
        pending = self.client.get("/api/endpoints?status=pending", headers=headers).json()
        self.assertEqual([(device["id"], device["has_device_key"]) for device in pending], [(str(endpoint_id), True)])
        self.assertNotIn("device_public_key", pending[0])
        self.assertEqual(self.client.put(f"/api/endpoints/{foreign_id}/client-certificate", headers=headers).status_code, 404)
        with patch.dict(os.environ, {"PERSISTGUARD_AGENT_CA_CERT_FILE": "", "PERSISTGUARD_AGENT_CA_KEY_FILE": ""}):
            self.assertEqual(self.client.put(route, headers=headers).status_code, 503)

        with patch.dict(os.environ, {"PERSISTGUARD_AGENT_CA_CERT_FILE": str(ca_file),
                                     "PERSISTGUARD_AGENT_CA_KEY_FILE": str(key_file)}):
            with patch.object(Session, "commit", side_effect=SQLAlchemyError("Audit commit failed")):
                self.assertEqual(self.client.put(route, headers=headers).status_code, 503)
            response = self.client.put(route, headers=headers)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

        issued = response.json()
        self.assertEqual(self.client.get("/api/endpoints?status=pending", headers=headers).json(), [])
        approved = self.client.get("/api/endpoints?status=approved", headers=headers).json()
        self.assertEqual([(device["id"], device["status"]) for device in approved], [(str(endpoint_id), "approved")])
        retry = self.client.put(route, headers=headers)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json(), issued)
        certificate = x509.load_pem_x509_certificate(issued["certificate_pem"].encode("ascii"))
        certificate.verify_directly_issued_by(ca)
        self.assertEqual(certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ), device_key)
        self.assertEqual(certificate.not_valid_after_utc, ca.not_valid_after_utc)
        self.assertEqual(certificate.serial_number, int(issued["certificate_serial"], 16))
        self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH])
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                         .get_values_for_type(x509.UniformResourceIdentifier), [f"urn:persistguard:endpoint:{endpoint_id}"])

        with Session(engine) as session, session.begin():
            self.assertEqual(session.get(Endpoint, endpoint_id).status, "approved")
            self.assertEqual(session.get(Endpoint, foreign_id).status, "pending")
            credential = session.get(AgentCredential, issued["certificate_serial"])
            self.assertEqual(credential.endpoint_id, endpoint_id)
            event = session.scalars(select(AuditEvent).where(AuditEvent.target_id == endpoint_id)).one()
            self.assertEqual((event.actor_id, event.action, event.status_code), (admin_id, "agent_credentials.issue", 201))
            old_serial = uuid4().hex
            session.add(AgentCredential(endpoint_id=endpoint_id, certificate_serial=old_serial,
                                        certificate_pem=credential.certificate_pem, expires_at=now,
                                        superseded_at=now))

        scan_route = f"/api/endpoints/{endpoint_id}/scan-jobs"
        completed_id = self.client.post(scan_route, headers=headers).json()["id"]
        with Session(engine) as session, session.begin():
            session.execute(update(ScanJob).where(ScanJob.id == completed_id).values(status="completed", finished_at=now))
        open_id = self.client.post(scan_route, headers=headers).json()["id"]
        with Session(engine) as session, session.begin():
            session.execute(update(ScanJob).where(ScanJob.id == open_id).values(status="dispatched"))
        revoke_route = f"/api/endpoints/{endpoint_id}/revoke"
        self.assertEqual(self.client.post(revoke_route).status_code, 401)
        self.assertEqual(self.client.post(revoke_route, headers={"Authorization": f"Bearer {token}"}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/endpoints/{foreign_id}/revoke", headers=headers).status_code, 404)
        with patch.object(Session, "commit", side_effect=SQLAlchemyError("Audit commit failed")):
            self.assertEqual(self.client.post(revoke_route, headers=headers).status_code, 503)
        self.assertEqual(self.client.get(f"/api/scan-jobs/{open_id}", headers=headers).json()["status"], "dispatched")
        self.assertEqual(self.client.get("/api/endpoints?status=approved", headers=headers).json(), approved)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: self.client.post(revoke_route, headers=headers), range(2)))
        for result in results:
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json(), {"endpoint_id": str(endpoint_id), "status": "revoked"})
        revoked = self.client.get("/api/endpoints?status=revoked", headers=headers).json()
        self.assertEqual([(device["id"], device["status"]) for device in revoked], [(str(endpoint_id), "revoked")])
        self.assertEqual(self.client.get("/api/endpoints?status=approved", headers=headers).json(), [])
        self.assertEqual(self.client.put(route, headers=headers).status_code, 409)
        self.assertEqual(self.client.post(scan_route, headers=headers).status_code, 409)
        self.assertEqual(self.client.get(f"/api/scan-jobs/{completed_id}", headers=headers).json()["status"], "completed")
        self.assertEqual(self.client.get(f"/api/scan-jobs/{open_id}", headers=headers).json()["status"], "canceled")
        with Session(engine) as session:
            self.assertIsNotNone(session.get(AgentCredential, issued["certificate_serial"]).revoked_at)
            self.assertIsNotNone(session.get(AgentCredential, old_serial).revoked_at)
            event = session.scalars(select(AuditEvent).where(
                AuditEvent.target_id == endpoint_id, AuditEvent.action == "endpoints.revoke",
            )).one()
            self.assertEqual((event.actor_id, event.status_code), (admin_id, 200))

    @unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
    def test_scan_queue_enforces_roles_and_tenant_scope_and_deduplicates_requests(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        self.enterContext(patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}))
        org_id, other_org_id, endpoint_id, foreign_id, pending_id = [uuid4() for _ in range(5)]

        def cleanup():
            with engine.begin() as connection:
                for model in (ScanJob, AuditEvent, Endpoint, User):
                    connection.execute(delete(model).where(model.organization_id.in_([org_id, other_org_id])))
                connection.execute(delete(Organization).where(Organization.id.in_([org_id, other_org_id])))

        self.addCleanup(cleanup)
        with Session(engine) as session, session.begin():
            own = Organization(id=org_id, name="Scan queue test")
            other = Organization(id=other_org_id, name="Other scan queue organization")
            session.add_all([
                Endpoint(id=endpoint_id, organization=own, hostname="ready", os_family="windows", status="approved"),
                Endpoint(id=pending_id, organization=own, hostname="pending", os_family="windows"),
                Endpoint(id=foreign_id, organization=other, hostname="foreign", os_family="windows", status="approved"),
            ])
            for name, role, organization in (
                ("admin", "admin", own), ("analyst", "analyst", own), ("viewer", "viewer", own), ("other", "admin", other),
            ):
                session.add(User(organization=organization, email=f"{name}@example.test", role=role,
                                 identity_issuer=self.issuer, identity_subject=f"{name}-{endpoint_id}"))

        def headers(name):
            return {"Authorization": f"Bearer {self.token(sub=f'{name}-{endpoint_id}')}"}

        route = f"/api/endpoints/{endpoint_id}/scan-jobs"
        for role, can_manage in (("admin", True), ("analyst", True), ("viewer", False)):
            targets = self.client.get("/api/scan-targets?query=READY", headers=headers(role))
            self.assertEqual(targets.status_code, 200)
            self.assertEqual(targets.json(), {"can_manage": can_manage, "can_onboard": role == "admin",
                                             "endpoints": [{"id": str(endpoint_id), "hostname": "ready"}]})
        self.assertEqual(self.client.get("/api/scan-targets", headers=headers("admin")).json()["endpoints"],
                         [{"id": str(endpoint_id), "hostname": "ready"}])
        self.assertEqual(self.client.post(route).status_code, 401)
        self.assertEqual(self.client.post(route, headers=headers("viewer")).status_code, 403)
        self.assertEqual(self.client.post(route, headers=headers("other")).status_code, 404)
        self.assertEqual(self.client.post(f"/api/endpoints/{pending_id}/scan-jobs", headers=headers("admin")).status_code, 409)

        with ThreadPoolExecutor(max_workers=2) as workers:
            requests = [workers.submit(self.client.post, route, headers=headers(name)) for name in ("admin", "analyst")]
            responses = [request.result(timeout=10) for request in requests]
        self.assertCountEqual([response.status_code for response in responses], [200, 201])
        job = responses[0].json()
        self.assertEqual(responses[1].json(), job)
        self.assertEqual((job["endpoint_id"], job["organization_id"]), (str(endpoint_id), str(org_id)))
        self.assertEqual((job["scan_type"], job["status"]), ("persistence_full_scan", "queued"))

        read_route = f"/api/scan-jobs/{job['id']}"
        self.assertEqual(self.client.get(read_route, headers=headers("viewer")).json(), job)
        self.assertEqual(self.client.get(read_route, headers=headers("other")).status_code, 404)
        self.assertEqual(self.client.get(read_route + "/result", headers=headers("viewer")).status_code, 404)
        self.assertEqual(self.client.get(read_route + "/assessment", headers=headers("viewer")).status_code, 404)

        with Session(engine) as session, session.begin():
            stored = session.scalars(select(ScanJob).where(ScanJob.organization_id == org_id)).one()
            self.assertEqual(str(stored.id), job["id"])
            event = session.scalars(select(AuditEvent).where(AuditEvent.target_id == stored.id)).one()
            self.assertEqual((event.action, event.actor_id, event.status_code), ("scan_jobs.queue", stored.requested_by, 201))
            stored.status = "partial"
            stored.finished_at = datetime.now(timezone.utc)
            stored.result = {"schema_version": 1, "status": "partial", "collectors": {
                "registry": {"status": "collected", "report": {"os_family": "windows", "entries": [], "coverage": []}},
                "scheduled_tasks": {"status": "error", "error": "task fixture unavailable"},
                "services": {"status": "partial", "report": {
                    "os_family": "windows", "entries": [{
                        "mechanism": "windows_service", "name": "Fixture", "display_name": "Fixture", "state": "stopped",
                        "command": "powershell.exe -EncodedCommand PLACEHOLDER", "known_malicious_hash": True,
                    }], "coverage": {"status": "partial", "issues": [{"name": "Restricted", "code": "access_denied"}]},
                }},
            }}

        saved = self.client.get(read_route + "/result", headers=headers("viewer"))
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json()["inventory"]["status"], "partial")
        self.assertEqual(self.client.get(read_route + "/result", headers=headers("other")).status_code, 404)

        assessment = self.client.get(read_route + "/assessment", headers=headers("viewer"))
        self.assertEqual(assessment.status_code, 200)
        self.assertEqual(assessment.headers["Cache-Control"], "no-store")
        data = assessment.json()
        self.assertIsNone(data["baseline_job_id"])
        self.assertEqual((data["scan_status"], data["status"], data["endpoint_id"]), ("partial", "partial", str(endpoint_id)))
        services = data["collectors"]["services"]
        self.assertEqual(services["coverage"][0]["issues"][0]["code"], "access_denied")
        finding, = services["assessments"]
        self.assertEqual((finding["score"], finding["verdict"], finding["reasons"]), (25, "unknown", ["Encoded startup command"]))
        self.assertEqual(data["collectors"]["scheduled_tasks"]["error"], "task fixture unavailable")
        self.assertEqual(self.client.get(read_route + "/assessment", headers=headers("other")).status_code, 404)

        with Session(engine) as session, session.begin():
            current = session.get(ScanJob, job["id"])
            baseline = ScanJob(organization_id=org_id, endpoint_id=endpoint_id, requested_by=current.requested_by,
                               scan_type=current.scan_type, status="completed", result=current.result,
                               finished_at=current.finished_at - timedelta(minutes=2))
            unrelated = ScanJob(organization_id=other_org_id, endpoint_id=foreign_id, requested_by=current.requested_by,
                                scan_type=current.scan_type, status="completed", result=current.result,
                                finished_at=current.finished_at - timedelta(minutes=1))
            session.add_all([baseline, unrelated])
            session.flush()
            baseline_id = str(baseline.id)
        assessed = self.client.get(read_route + "/assessment", headers=headers("viewer")).json()
        self.assertEqual(assessed["baseline_job_id"], baseline_id)
        self.assertEqual(assessed["collectors"]["services"]["assessments"][0]["baseline_status"], "unknown")

        response = self.client.post(route, headers=headers("analyst"))
        self.assertEqual(response.status_code, 201)
        self.assertNotEqual(response.json()["id"], job["id"])
        queued = response.json()
        foreign = self.client.post(f"/api/endpoints/{foreign_id}/scan-jobs", headers=headers("other"))
        self.assertEqual(foreign.status_code, 201)
        listing = self.client.get("/api/scan-jobs?status=queued", headers=headers("viewer"))
        self.assertEqual(listing.json(), [queued])
        self.assertEqual(self.client.get("/api/scan-jobs?status=queued&offset=1", headers=headers("viewer")).json(), [])
        cancel = f"/api/scan-jobs/{queued['id']}/cancel"
        self.assertEqual(self.client.post(cancel, headers=headers("other")).status_code, 404)
        self.assertEqual(self.client.post(cancel, headers=headers("viewer")).status_code, 403)
        canceled = self.client.post(cancel, headers=headers("analyst"))
        self.assertEqual(canceled.status_code, 200)
        self.assertEqual(canceled.json()["status"], "canceled")
        self.assertEqual(self.client.post(cancel, headers=headers("admin")).json(), canceled.json())
        self.assertEqual(self.client.get("/api/scan-jobs?status=canceled", headers=headers("viewer")).json(), [canceled.json()])

        scope = {"scan_type": "persistence_services_scan"}
        self.assertEqual(self.client.post(route, headers=headers("viewer"), json=scope).status_code, 403)
        self.assertEqual(self.client.post(route, headers=headers("other"), json=scope).status_code, 404)
        self.assertEqual(self.client.post(route, headers=headers("admin"), json={"scan_type": "unknown"}).status_code, 422)
        new_job = self.client.post(route, headers=headers("analyst"), json=scope)
        self.assertEqual(new_job.status_code, 201)
        racing_id = new_job.json()["id"]
        self.assertNotEqual(racing_id, queued["id"])
        self.assertEqual(new_job.json()["scan_type"], scope["scan_type"])
        self.assertEqual(self.client.post(route, headers=headers("admin"), json=scope).json(), new_job.json())
        self.assertEqual(self.client.post(route, headers=headers("admin")).status_code, 409)

        def dispatch():
            with Session(engine) as session, session.begin():
                return session.scalar(update(ScanJob).where(ScanJob.id == racing_id, ScanJob.status == "queued")
                                      .values(status="dispatched").returning(ScanJob.id))

        with ThreadPoolExecutor(max_workers=2) as workers:
            dispatcher = workers.submit(dispatch)
            cancellation = workers.submit(self.client.post, f"/api/scan-jobs/{racing_id}/cancel", headers=headers("admin"))
            dispatch_won = dispatcher.result(timeout=10) is not None
            self.assertEqual(cancellation.result(timeout=10).status_code, 409 if dispatch_won else 200)
        with Session(engine) as session:
            self.assertEqual(session.get(ScanJob, racing_id).status, "dispatched" if dispatch_won else "canceled")
            cancel_event = session.scalars(select(AuditEvent).where(AuditEvent.target_id == queued["id"],
                                                                   AuditEvent.action == "scan_jobs.cancel")).one()
            self.assertEqual(cancel_event.status_code, 200)

        with Session(engine) as session, session.begin():
            full = session.get(ScanJob, job["id"])
            target = session.get(ScanJob, racing_id)
            target.status = "partial"
            target.result = {"collectors": {"services": full.result["collectors"]["services"]}}
            target.finished_at = full.finished_at + timedelta(minutes=2)
            session.add(ScanJob(organization_id=org_id, endpoint_id=endpoint_id, requested_by=full.requested_by,
                                scan_type="persistence_registry_scan", status="completed",
                                result={"collectors": {"registry": full.result["collectors"]["registry"]}},
                                finished_at=full.finished_at + timedelta(minutes=1)))
        targeted = self.client.get(f"/api/scan-jobs/{racing_id}/assessment", headers=headers("viewer")).json()
        self.assertEqual(targeted["baseline_job_id"], job["id"])
        self.assertEqual(set(targeted["collectors"]), {"services"})
        self.assertEqual(targeted["status"], "partial")

    def test_invalid_tokens(self):
        tokens = {
            "malformed": "invalid",
            "wrong signature": self.token(signing_key=self.other_key),
            "wrong issuer": self.token(iss="https://other.example.test/"),
            "wrong audience": self.token(aud="other-api"),
            "expired": self.token(exp=datetime.now(timezone.utc) - timedelta(minutes=1)),
            "missing expiration": self.token(exp=None),
            "invalid expiration type": self.token(exp={}),
            "empty subject": self.token(sub=" "),
        }
        for name, token in tokens.items():
            with self.subTest(name=name):
                response = self.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")

    def test_missing_token(self):
        response = self.client.get("/api/me")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")
        self.assertEqual(self.client.get("/healthz").status_code, 200)

    def test_missing_auth_configuration(self):
        with patch.dict(os.environ, {"PERSISTGUARD_AUTH_PUBLIC_KEY_FILE": ""}):
            response = self.client.get("/api/me", headers={"Authorization": f"Bearer {self.token()}"})
        self.assertEqual(response.status_code, 503)
