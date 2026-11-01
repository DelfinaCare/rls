import os
import unittest

import sqlalchemy
import testing.postgresql
from alembic import autogenerate
from alembic import command
from alembic import config as alembic_config
from alembic import operations
from alembic.runtime import migration

from rls import alembic_ops
from test import expectations
from test import models


class TestAlembicOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup temporary PostgreSQL database
        cls.postgresql = testing.postgresql.PostgresqlFactory(
            cache_initialized_db=True
        )()
        cls.engine_url = sqlalchemy.make_url(cls.postgresql.url()).set(
            drivername="postgresql+psycopg"
        )

        # Initialize Alembic configuration
        cls.alembic_cfg = alembic_config.Config(
            os.path.join(os.path.dirname(__file__), "./alembic.ini")
        )
        cls.alembic_cfg.set_main_option("sqlalchemy.url", str(cls.engine_url))
        cls.alembic_cfg.set_main_option(
            "script_location", os.path.join(os.path.dirname(__file__), "./alembic")
        )

        cls.admin_engine = sqlalchemy.create_engine(cls.engine_url)
        cls.connection = cls.admin_engine.connect()

    @classmethod
    def tearDownClass(cls):
        cls.admin_engine.dispose()
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

    def test_no_spurious_diffs_after_migration(self):
        """After applying migrations, autogenerating again should produce no changes."""
        command.upgrade(self.alembic_cfg, "head")

        target_metadata = models.Base.metadata
        with self.admin_engine.connect() as conn:
            ctx = migration.MigrationContext.configure(conn)
            diffs = autogenerate.compare_metadata(ctx, target_metadata)

        self.assertEqual(
            diffs,
            [],
            f"Expected no spurious diffs after migration, but found: {diffs}",
        )


class TestStrictPolicyMigrationReversal(unittest.TestCase):
    """A policy with allow_bypass_rls=False must stay strict across upgrade/downgrade."""

    TABLE = "strict_docs"
    POLICY = "strict_docs_select_policy"
    ROLE = "strict_docs_reader"
    EXPR = (
        "owner_id = CAST(NULLIF(current_setting('rls.account_id', true), '') "
        "AS INTEGER)"
    )

    @classmethod
    def setUpClass(cls):
        cls.postgresql = testing.postgresql.PostgresqlFactory(
            cache_initialized_db=True
        )()
        cls.engine = sqlalchemy.create_engine(
            sqlalchemy.make_url(cls.postgresql.url()).set(
                drivername="postgresql+psycopg"
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.postgresql.stop()

    def setUp(self):
        with self.engine.begin() as conn:
            conn.execute(
                sqlalchemy.text(
                    f"CREATE TABLE {self.TABLE} (id INTEGER, owner_id INTEGER);"
                    f"INSERT INTO {self.TABLE} VALUES (1, 1), (2, 2);"
                    f"ALTER TABLE {self.TABLE} ENABLE ROW LEVEL SECURITY;"
                    f"CREATE ROLE {self.ROLE} NOLOGIN;"
                    f"GRANT SELECT ON {self.TABLE} TO {self.ROLE};"
                )
            )

    def tearDown(self):
        with self.engine.begin() as conn:
            conn.execute(
                sqlalchemy.text(f"DROP TABLE {self.TABLE}; DROP ROLE {self.ROLE};")
            )

    def _invoke(self, op):
        with self.engine.begin() as conn:
            ctx = migration.MigrationContext.configure(conn)
            operations.Operations(ctx).invoke(op)

    def _db_policies(self):
        with self.engine.connect() as conn:
            return alembic_ops.check_rls_policies(conn, None, self.TABLE)

    def _visible_ids_with_bypass(self):
        """Rows visible to a non-superuser for account 1 with rls.bypass_rls on."""
        with self.engine.begin() as conn:
            conn.execute(sqlalchemy.text(f"SET LOCAL ROLE {self.ROLE}"))
            conn.execute(sqlalchemy.text("SET LOCAL rls.account_id = '1'"))
            conn.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = 'true'"))
            return sorted(
                conn.execute(sqlalchemy.text(f"SELECT id FROM {self.TABLE}"))
                .scalars()
                .all()
            )

    def _assert_strict(self):
        policies = self._db_policies()
        self.assertEqual(len(policies), 1)
        self.assertNotIn("rls.bypass_rls", policies[0].expression)
        self.assertFalse(policies[0].allow_bypass_rls)
        self.assertEqual(self._visible_ids_with_bypass(), [1])

    def test_strict_policy_survives_upgrade_and_downgrade(self):
        create_op = alembic_ops.CreatePolicyOp(
            table_name=self.TABLE,
            policy_name=self.POLICY,
            definition="PERMISSIVE",
            cmd="SELECT",
            expr=self.EXPR,
            allow_bypass_rls=False,
        )

        # Migration 1 upgrade: create the strict policy.
        self._invoke(create_op)
        self._assert_strict()

        # Migration 1 downgrade then re-upgrade.
        self._invoke(create_op.reverse())
        self.assertEqual(self._db_policies(), [])
        self._invoke(create_op.reverse().reverse())
        self._assert_strict()

        # Migration 2 upgrade: drop the policy as read back from PostgreSQL,
        # mirroring what autogenerate emits for a removed policy.
        db_policy = self._db_policies()[0]
        drop_op = alembic_ops.DropPolicyOp(
            table_name=self.TABLE,
            policy_name=db_policy.custom_policy_name,
            definition=db_policy.definition,
            cmd=db_policy.cmd.value,
            expr=db_policy.expression,
            allow_bypass_rls=db_policy.allow_bypass_rls,
        )
        self._invoke(drop_op)
        self.assertEqual(self._db_policies(), [])

        # Migration 2 downgrade: the recreated policy must still be strict.
        self._invoke(drop_op.reverse())
        self._assert_strict()

    def test_drop_without_flag_does_not_make_policy_bypassable(self):
        """Existing migrations that omit allow_bypass_rls must not add bypass."""
        self._invoke(
            alembic_ops.CreatePolicyOp(
                table_name=self.TABLE,
                policy_name=self.POLICY,
                definition="PERMISSIVE",
                cmd="SELECT",
                expr=self.EXPR,
                allow_bypass_rls=False,
            )
        )
        drop_op = alembic_ops.DropPolicyOp(
            table_name=self.TABLE,
            policy_name=self.POLICY,
            definition="PERMISSIVE",
            cmd="SELECT",
            expr=self._db_policies()[0].expression,
        )
        self._invoke(drop_op)
        self._invoke(drop_op.reverse())
        self._assert_strict()


if __name__ == "__main__":
    unittest.main()
