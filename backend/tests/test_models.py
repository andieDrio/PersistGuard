import os
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from persistguard.models import Endpoint, Organization, User


TEST_DATABASE_URL = os.environ.get("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class ModelTests(unittest.TestCase):
    def test_create_and_read_organization_user_and_endpoint(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)

        with engine.connect() as connection, connection.begin() as transaction:
            try:
                with Session(connection) as session:
                    organization = Organization(name="PersistGuard model test")
                    user = User(organization=organization, email="analyst@example.test", role="analyst")
                    endpoint = Endpoint(organization=organization, hostname="test-host", os_family="windows")
                    session.add_all([user, endpoint])
                    session.flush()
                    organization_id, user_id, endpoint_id = organization.id, user.id, endpoint.id

                with Session(connection) as session:
                    organization = session.get(Organization, organization_id)
                    user = session.get(User, user_id)
                    endpoint = session.get(Endpoint, endpoint_id)
                    self.assertEqual(organization.name, "PersistGuard model test")
                    self.assertEqual(organization.status, "active")
                    self.assertEqual(user.email, "analyst@example.test")
                    self.assertEqual(user.organization.id, organization_id)
                    self.assertEqual(endpoint.hostname, "test-host")
                    self.assertEqual(endpoint.organization.id, organization_id)
                    self.assertEqual(endpoint.status, "pending")
                    self.assertIsNone(endpoint.last_seen)
            finally:
                transaction.rollback()
