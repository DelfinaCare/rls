import os
import unittest

import sqlalchemy
import testing.postgresql
from alembic import autogenerate
from alembic import command
from alembic import config as alembic_config
from alembic.runtime import migration

from rls import alembic_ops
from test import expectations
from test import models


class TestAlembicOperations(unittest.TestCase):
    alembic_cfg: alembic_config.Config
    admin_engine: sqlalchemy.Engine

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
            migration_script = autogenerate.produce_migrations(ctx, target_metadata)

        self.assertEqual(
            diffs,
            [],
            f"Expected no spurious diffs after migration, but found: {diffs}",
        )
        self.assertTrue(
            migration_script.upgrade_ops is not None
            and migration_script.upgrade_ops.is_empty(),
            "Expected no spurious RLS operations after migration.",
        )

    def _policy_names(self, tablename: str) -> set[str]:
        with self.admin_engine.connect() as conn:
            return set(
                conn.execute(
                    sqlalchemy.text(
                        "SELECT policyname FROM pg_policies WHERE tablename = :t"
                    ),
                    {"t": tablename},
                ).scalars()
            )

    def _pending_policy_ops(self) -> tuple[list[str], list[str]]:
        """Return (dropped, created) policy names autogenerate would emit."""
        with self.admin_engine.connect() as conn:
            ctx = migration.MigrationContext.configure(conn)
            script = autogenerate.produce_migrations(ctx, models.Base.metadata)
        assert script.upgrade_ops is not None
        dropped = []
        created = []
        for table_ops in script.upgrade_ops.ops:
            for op in getattr(table_ops, "ops", []):
                if isinstance(op, alembic_ops.DropPolicyOp):
                    dropped.append(op.policy_name)
                elif isinstance(op, alembic_ops.CreatePolicyOp):
                    created.append(op.policy_name)
        return dropped, created

    def _autogenerate_and_upgrade(self, message: str) -> None:
        command.revision(self.alembic_cfg, message=message, autogenerate=True)
        command.upgrade(self.alembic_cfg, "head")

    def test_policy_rename(self):
        """Renaming a policy in metadata drops the old policy and creates the new one."""
        self._autogenerate_and_upgrade("ensure policies exist")
        policy = models.Item.__rls_policies__[1]
        old_name = policy.custom_policy_name
        policy.get_sql_policies(table_name="items", name_suffix="1")
        [old_policy_name] = policy.policy_names
        self.assertIn(old_policy_name, self._policy_names("items"))

        try:
            policy.custom_policy_name = "renamed_policy"
            policy.get_sql_policies(table_name="items", name_suffix="1")
            [new_policy_name] = policy.policy_names
            self.assertTrue(
                new_policy_name.startswith("items_renamed_policy_select_1_")
            )

            dropped, created = self._pending_policy_ops()
            self.assertEqual(dropped, [old_policy_name])
            self.assertEqual(created, [new_policy_name])

            self._autogenerate_and_upgrade("rename policy")
            names = self._policy_names("items")
            self.assertIn(new_policy_name, names)
            self.assertNotIn(old_policy_name, names)
            self.assertEqual(self._pending_policy_ops(), ([], []))
        finally:
            policy.custom_policy_name = old_name
            self._autogenerate_and_upgrade("restore policy name")

        names = self._policy_names("items")
        self.assertIn(old_policy_name, names)
        self.assertNotIn(new_policy_name, names)

    def test_migrates_policies_from_legacy_names(self):
        """Policies named with the pre-hash scheme are replaced by hashed names."""
        self._autogenerate_and_upgrade("ensure policies exist")
        expected_names = {
            p["policyname"]
            for p in expectations.EXPECTED_POLICIES
            if p["policyname"].startswith("users_")
        }
        self.assertEqual(self._policy_names("users"), expected_names)

        # Simulate a database created before policy names carried a hash.
        legacy_names = set()
        with self.admin_engine.begin() as conn:
            for name in expected_names:
                cmd = "select" if "_select_" in name else "update"
                legacy_name = f"users_equal_to_accountid_policy_{cmd}_policy_0"
                legacy_names.add(legacy_name)
                conn.execute(
                    sqlalchemy.text(
                        f"ALTER POLICY {name} ON users RENAME TO {legacy_name}"
                    )
                )
        self.assertEqual(self._policy_names("users"), legacy_names)

        dropped, created = self._pending_policy_ops()
        self.assertEqual(set(dropped), legacy_names)
        self.assertEqual(set(created), expected_names)

        self._autogenerate_and_upgrade("migrate legacy policy names")
        self.assertEqual(self._policy_names("users"), expected_names)
        self.assertEqual(self._pending_policy_ops(), ([], []))


if __name__ == "__main__":
    unittest.main()
