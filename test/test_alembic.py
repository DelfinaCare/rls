import unittest
from alembic.config import Config
from alembic import command
import os
import testing.postgresql
from sqlalchemy import text, create_engine


class TestAlembicOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup temporary PostgreSQL database
        cls.postgresql = testing.postgresql.PostgresqlFactory(
            cache_initialized_db=True
        )()
        cls.engine_url = cls.postgresql.url()

        # Initialize Alembic configuration
        cls.alembic_cfg = Config(
            os.path.join(os.path.dirname(__file__), "./alembic.ini")
        )
        cls.alembic_cfg.set_main_option("sqlalchemy.url", cls.engine_url)
        cls.alembic_cfg.set_main_option(
            "script_location", os.path.join(os.path.dirname(__file__), "./alembic")
        )

        cls.admin_engine = create_engine(cls.engine_url)
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
                    text(
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

            # TODO: encapsulate duplicated test code
            expected_policies = [
                {
                    "policyname": "items_smaller_than_or_equal_accountid_policy_all_policy_2",
                    "permissive": "PERMISSIVE",
                    "cmd": "ALL",
                    "qual": "((owner_id <= (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_greater_than_accountid_policy_select_policy_1",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id > (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                    "with_check": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
            ]

            for policy in expected_policies:
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
