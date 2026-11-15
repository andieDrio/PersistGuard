import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.client_certificates import issue_client_certificate
from persistguard.models import AgentCredential, AuditEvent, Endpoint, Organization


TEST_DATABASE_URL = os.getenv("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class RotationTests(unittest.TestCase):
    def test_rotation_retries_and_retires_predecessor_only_after_confirmation(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        org_id, endpoint_id = uuid4(), uuid4()

        def remove_fixture():
            with engine.begin() as connection:
                connection.execute(delete(AgentCredential).where(AgentCredential.endpoint_id == endpoint_id))
                connection.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
                connection.execute(delete(Endpoint).where(Endpoint.id == endpoint_id))
                connection.execute(delete(Organization).where(Organization.id == org_id))

        self.addCleanup(remove_fixture)
        ca_dir = Path(self.enterContext(TemporaryDirectory()))
        ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rotation test CA")])
        now = datetime.now(timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
              .not_valid_after(now + timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
              .sign(ca_key, hashes.SHA256()))
        ca_cert, ca_private = ca_dir / "ca.pem", ca_dir / "ca-key.pem"
        ca_cert.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        ca_private.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        secret = token_hex(32)
        self.enterContext(patch.dict(os.environ, {
            "PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL,
            "PERSISTGUARD_AGENT_CA_CERT_FILE": str(ca_cert),
            "PERSISTGUARD_AGENT_CA_KEY_FILE": str(ca_private),
            "PERSISTGUARD_ROTATION_SECRET": secret,
        }))
        device_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with patch("persistguard.client_certificates.CLIENT_CERTIFICATE_LIFETIME", timedelta(hours=1)):
            old = issue_client_certificate(endpoint_id, device_key)
        old_serial = format(old.serial_number, "x")
        with Session(engine) as session, session.begin():
            org = Organization(id=org_id, name="Rotation test")
            session.add(Endpoint(id=endpoint_id, organization=org, hostname="test", os_family="windows",
                                 status="approved", device_public_key=device_key))
            session.flush()
            session.add(AgentCredential(certificate_serial=old_serial, endpoint_id=endpoint_id,
                                        certificate_pem=old.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                                        expires_at=old.not_valid_after_utc))

        def proof(certificate):
            return {"endpoint_id": str(endpoint_id), "certificate_serial": format(certificate.serial_number, "x"),
                    "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex()}

        path = "/internal/agent/certificate/"
        headers = {"Authorization": f"Bearer {secret}"}
        old_proof = proof(old)
        with TestClient(app) as client:
            self.assertEqual(client.post(path + "renew", json=old_proof).status_code, 401)
            wrong_proof = {**old_proof, "certificate_sha256": "0" * 64}
            self.assertEqual(client.post(path + "renew", json=wrong_proof, headers=headers).status_code, 403)
            self.assertEqual(client.post(path + "confirm", json=old_proof, headers=headers).status_code, 409)
            response = client.post(path + "renew", json=old_proof, headers=headers)
            self.assertEqual(response.status_code, 200)
            replacement = response.json()
            new = x509.load_pem_x509_certificate(replacement["certificate_pem"].encode("ascii"))
            new.verify_directly_issued_by(ca)
            self.assertGreater(new.not_valid_after_utc, old.not_valid_after_utc)
            self.assertEqual(client.post(path + "renew", json=old_proof, headers=headers).json(), replacement)
            new_proof = proof(new)
            self.assertEqual(client.post(path + "renew", json=new_proof, headers=headers).json(), replacement)
            with Session(engine) as session:
                self.assertIsNone(session.get(AgentCredential, old_serial).revoked_at)

            for _ in range(2):
                response = client.post(path + "confirm", json=new_proof, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {"confirmed": True})
            self.assertEqual(client.post(path + "renew", json=old_proof, headers=headers).status_code, 403)

        with Session(engine) as session:
            credentials = session.scalars(select(AgentCredential).where(AgentCredential.endpoint_id == endpoint_id)).all()
            self.assertEqual(len(credentials), 2)
            self.assertIsNotNone(session.get(AgentCredential, old_serial).revoked_at)
            events = session.scalars(select(AuditEvent).where(AuditEvent.target_id == endpoint_id)).all()
            self.assertCountEqual([event.action for event in events], ["agent_credentials.renew", "agent_credentials.confirm"])
