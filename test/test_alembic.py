import os
import unittest

import sqlalchemy
import testing.postgresql
from alembic import command
from alembic import config as alembic_config

from test import database, expectations


class TestAlembicOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup temporary PostgreSQL database
        cls.postgresql = testing.postgresql.PostgresqlFactory(
            cache_initialized_db=True
        )()
        cls.engine_url = database.psycopg3_url(cls.postgresql.url())

        # Initialize Alembic configuration
        cls.alembic_cfg = alembic_config.Config(
            os.path.join(os.path.dirname(__file__), "./alembic.ini")
        )
        cls.alembic_cfg.set_main_option("sqlalchemy.url", cls.engine_url)
        cls.alembic_cfg.set_main_option(
            "script_location", os.path.join(os.path.dirname(__file__), "./alembic")
        )

        cls.admin_engine = sqlalchemy.create_engine(cls.engine_url)
        cls.connection = cls.admin_engine.connect()

    @classmethod
    def tearDownClass(cls):
        cls.postgresql.stop()

    def test_custom_migration(self):
        # Upgrade database to the latest revision
        command.upgrade(self.alembic_cfg, "head")
        # Generate a migration script with custom operations
        command.revision(
            self.alembic_cfg, message="test custom operation", autogenerate=True
        )
        # Apply migrations
        command.upgrade(self.alembic_cfg, "head")

        # Validate custom operations
        with self.connection.begin():
            # Check if the policies are created
            policies = (
                self.connection.execute(
                    sqlalchemy.text(
                        """
                SELECT policyname, permissive, qual, with_check, cmd
                FROM pg_policies
                WHERE tablename IN ('items', 'users');
                """
                    )
                )
                .mappings()
                .fetchall()
            )

            self.assertTrue(len(policies) == 6, "Expected 6 policies to be created")

            for policy in expectations.EXPECTED_POLICIES:
                matched_policy = next(
                    (p for p in policies if p["policyname"] == policy["policyname"]),
                    None,
                )

                self.assertIsNotNone(
                    matched_policy,
                    f"Expected policy '{policy['policyname']}' to exist.",
                )

                for key, value in policy.items():
                    self.assertEqual(
                        matched_policy[key],
                        value,
                        f"Expected policy '{policy['policyname']}' to have '{key}'='{value}'.",
                    )


if __name__ == "__main__":
    unittest.main()
