import os
import typing
import unittest

import sqlalchemy
import testing.postgresql
from alembic import autogenerate
from alembic import command
from alembic import config as alembic_config
from alembic import operations as alembic_operations
from alembic.operations import ops as alembic_ops_module
from alembic.runtime import migration
from sqlalchemy import orm

from rls import alembic_ops
from rls import policy
from rls import register
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
                SELECT tablename, policyname, permissive, qual, with_check, cmd
                FROM pg_policies
                WHERE tablename IN ('items', 'users');
                """
                    )
                )
                .mappings()
                .fetchall()
            )

            self.assertTrue(len(policies) == 4, "Expected 4 policies to be created")

            for expected in expectations.EXPECTED_POLICIES:
                matched_policy = next(
                    (p for p in policies if p["policyname"] == expected["policyname"]),
                    None,
                )

                self.assertIsNotNone(
                    matched_policy,
                    f"Expected policy '{expected['policyname']}' to exist.",
                )

                for key, value in expected.items():
                    self.assertEqual(
                        matched_policy[key],
                        value,
                        f"Expected policy '{expected['policyname']}' to have '{key}'='{value}'.",
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
        old_policy = models.Item.__rls_policies__[1]
        old_policy_name = old_policy.name
        self.assertIn(old_policy_name, self._policy_names("items"))

        new_policy = policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.sql.column("owner_id") > x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.select,
            name="renamed_policy",
        )
        new_policy_name = new_policy.name
        self.assertTrue(new_policy_name.startswith("renamed_policy_"))

        try:
            models.Item.__rls_policies__[1] = new_policy

            dropped, created = self._pending_policy_ops()
            self.assertEqual(dropped, [old_policy_name])
            self.assertEqual(created, [new_policy_name])

            self._autogenerate_and_upgrade("rename policy")
            names = self._policy_names("items")
            self.assertIn(new_policy_name, names)
            self.assertNotIn(old_policy_name, names)
            self.assertEqual(self._pending_policy_ops(), ([], []))
        finally:
            models.Item.__rls_policies__[1] = old_policy
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
            if p["tablename"] == "users"
        }
        self.assertEqual(self._policy_names("users"), expected_names)

        # Simulate a database created before policy names carried a hash.
        legacy_names = set()
        with self.admin_engine.begin() as conn:
            for ix, name in enumerate(sorted(expected_names)):
                legacy_name = f"users_equal_to_accountid_policy_all_policy_{ix}"
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

    def _rls_flags(self, tablename: str, schemaname: str = "public") -> tuple:
        with self.admin_engine.connect() as conn:
            row = conn.execute(
                sqlalchemy.text(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = :s AND c.relname = :t"
                ),
                {"s": schemaname, "t": tablename},
            ).one()
        return tuple(row)

    def test_migration_forces_rls(self):
        """Migrations enable and force RLS so table owners are also subject to it."""
        self._autogenerate_and_upgrade("ensure policies exist")
        for tablename in ("users", "items"):
            self.assertEqual(self._rls_flags(tablename), (True, True))

    def test_forces_rls_on_tables_enabled_without_force(self):
        """Tables migrated before FORCE was emitted are forced by the next migration."""
        self._autogenerate_and_upgrade("ensure policies exist")
        with self.admin_engine.begin() as conn:
            conn.execute(
                sqlalchemy.text("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
            )
        self.assertEqual(self._rls_flags("users"), (True, False))
        self._autogenerate_and_upgrade("force rls")
        self.assertEqual(self._rls_flags("users"), (True, True))
        self.assertEqual(self._pending_policy_ops(), ([], []))

    def test_schema_qualified_table(self):
        """Autogenerate creates, applies and then keeps policies on a table in a
        non-default schema."""
        schema = "rls_schema_test"

        class SchemaBase(orm.DeclarativeBase):
            pass

        register.base_wrapper(SchemaBase)

        class Doc(SchemaBase):
            __tablename__ = "docs"
            __table_args__ = ({"schema": schema},)
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            __rls_policies__: typing.ClassVar[list[policy.Policy]] = [
                policy.Policy.from_sqla(
                    expr=lambda x: sqlalchemy.sql.column("owner_id") == x,
                    condition_args=[
                        policy.ConditionArg(
                            comparator_name="account_id", type=sqlalchemy.Integer
                        ),
                    ],
                    cmd=policy.Command.all,
                ),
            ]

        def include_name(name, type_, parent_names):
            return type_ != "schema" or name == schema

        def docs_ops() -> list:
            with self.admin_engine.connect() as conn:
                ctx = migration.MigrationContext.configure(
                    conn,
                    opts={
                        "include_schemas": True,
                        "include_name": include_name,
                        "target_metadata": SchemaBase.metadata,
                    },
                )
                script = autogenerate.produce_migrations(ctx, SchemaBase.metadata)
            assert script.upgrade_ops is not None
            return [
                op
                for table_ops in script.upgrade_ops.ops
                if isinstance(table_ops, alembic_ops_module.ModifyTableOps)
                and table_ops.table_name == "docs"
                for op in table_ops.ops
            ]

        with self.admin_engine.begin() as conn:
            conn.execute(sqlalchemy.text(f"CREATE SCHEMA {schema}"))
            SchemaBase.metadata.create_all(conn)
        self.addCleanup(self._drop_schema, schema)

        ops = docs_ops()
        self.assertEqual(
            [type(op) for op in ops],
            [alembic_ops.EnableRlsOp, alembic_ops.CreatePolicyOp],
        )
        self.assertTrue(all(op.schemaname == schema for op in ops))

        with self.admin_engine.begin() as conn:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(conn)
            )
            for op in ops:
                operations.invoke(op)

        self.assertEqual(self._rls_flags("docs", schema), (True, True))
        with self.admin_engine.connect() as conn:
            names = set(
                conn.execute(
                    sqlalchemy.text(
                        "SELECT policyname FROM pg_policies "
                        "WHERE schemaname = :s AND tablename = 'docs'"
                    ),
                    {"s": schema},
                ).scalars()
            )
        self.assertEqual(names, {Doc.__rls_policies__[0].name})
        # Once applied, autogenerate must not disable RLS or drop the policy.
        self.assertEqual(docs_ops(), [])

    def _drop_schema(self, schema: str) -> None:
        with self.admin_engine.begin() as conn:
            conn.execute(sqlalchemy.text(f"DROP SCHEMA {schema} CASCADE"))


if __name__ == "__main__":
    unittest.main()
