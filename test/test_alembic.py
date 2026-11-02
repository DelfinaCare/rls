import os
import typing
import unittest
from unittest import mock

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
from rls import create_policies
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

    def _pending_enable_ops(self) -> list[alembic_ops.EnableRlsOp]:
        with self.admin_engine.connect() as conn:
            ctx = migration.MigrationContext.configure(conn)
            script = autogenerate.produce_migrations(ctx, models.Base.metadata)
        assert script.upgrade_ops is not None
        return [
            op
            for table_ops in script.upgrade_ops.ops
            for op in getattr(table_ops, "ops", [])
            if isinstance(op, alembic_ops.EnableRlsOp)
        ]

    def test_enable_only_rls_mode(self):
        """Tables in ``enable`` mode have RLS enabled but not forced."""
        self._autogenerate_and_upgrade("ensure policies exist")
        self.assertEqual(self._rls_flags("users"), (True, True))
        try:
            with mock.patch.object(
                models.User, "__rls_mode__", policy.RlsMode.enable, create=True
            ):
                self._autogenerate_and_upgrade("enable only rls")
                self.assertEqual(self._rls_flags("users"), (True, False))
                self.assertEqual(self._rls_flags("items"), (True, True))
                self.assertEqual(self._pending_enable_ops(), [])
        finally:
            self._autogenerate_and_upgrade("restore forced rls")
        self.assertEqual(self._rls_flags("users"), (True, True))
        self.assertEqual(self._pending_enable_ops(), [])

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

    def _make_quoting_base(self) -> type[orm.DeclarativeBase]:
        """Return a base with reserved-word, mixed-case and mixed-case-schema
        tables, whose policy names need quoting."""

        class QuotingBase(orm.DeclarativeBase):
            pass

        register.base_wrapper(QuotingBase)

        def owner_policies() -> list[policy.Policy]:
            return [
                policy.Policy.from_sqla(
                    expr=lambda x: sqlalchemy.sql.column("owner_id") == x,
                    condition_args=[
                        policy.ConditionArg(
                            comparator_name="account_id", type=sqlalchemy.Integer
                        ),
                    ],
                    cmd=policy.Command.all,
                    name="Owner Policy",
                ),
            ]

        class Order(QuotingBase):
            __tablename__ = "order"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            __rls_policies__ = owner_policies()

        class MixedCase(QuotingBase):
            __tablename__ = "MixedCase"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            __rls_policies__ = owner_policies()

        class MixedSchema(QuotingBase):
            __tablename__ = "MixedTable"
            __table_args__ = ({"schema": "MixedSchema"},)
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            __rls_policies__ = owner_policies()

        self.assertIsNotNone((Order, MixedCase, MixedSchema))
        return QuotingBase

    def _quoting_table_ops(self, metadata: sqlalchemy.MetaData) -> list:
        def include_name(name, type_, parent_names):
            return type_ != "schema" or name in (None, "public", "MixedSchema")

        def include_object(obj, name, type_, reflected, compare_to):
            return type_ != "table" or name in ("order", "MixedCase", "MixedTable")

        with self.admin_engine.connect() as conn:
            ctx = migration.MigrationContext.configure(
                conn,
                opts={
                    "include_schemas": True,
                    "include_name": include_name,
                    "include_object": include_object,
                    "target_metadata": metadata,
                },
            )
            script = autogenerate.produce_migrations(ctx, metadata)
        assert script.upgrade_ops is not None
        return [
            op
            for table_ops in script.upgrade_ops.ops
            if isinstance(table_ops, alembic_ops_module.ModifyTableOps)
            for op in table_ops.ops
        ]

    def _drop_quoting_tables(self, metadata: sqlalchemy.MetaData) -> None:
        with self.admin_engine.begin() as conn:
            metadata.drop_all(conn)
            conn.execute(sqlalchemy.text('DROP SCHEMA "MixedSchema" CASCADE'))

    def _quoting_policy_names(self) -> set[tuple[str, str, str]]:
        with self.admin_engine.connect() as conn:
            return {
                tuple(row)
                for row in conn.execute(
                    sqlalchemy.text(
                        "SELECT schemaname, tablename, policyname FROM pg_policies "
                        "WHERE tablename IN ('order', 'MixedCase', 'MixedTable')"
                    )
                )
            }

    def test_alembic_ops_quote_identifiers(self):
        """Autogenerated RLS ops work on reserved-word and mixed-case names."""
        QuotingBase = self._make_quoting_base()
        with self.admin_engine.begin() as conn:
            conn.execute(sqlalchemy.text('CREATE SCHEMA "MixedSchema"'))
            QuotingBase.metadata.create_all(conn)
        self.addCleanup(self._drop_quoting_tables, QuotingBase.metadata)

        ops = self._quoting_table_ops(QuotingBase.metadata)
        self.assertEqual(
            sorted(type(op).__name__ for op in ops),
            ["CreatePolicyOp"] * 3 + ["EnableRlsOp"] * 3,
        )
        with self.admin_engine.begin() as conn:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(conn)
            )
            for op in ops:
                operations.invoke(op)

        self.assertEqual(self._rls_flags("order"), (True, True))
        self.assertEqual(self._rls_flags("MixedCase"), (True, True))
        self.assertEqual(self._rls_flags("MixedTable", "MixedSchema"), (True, True))
        policy_name = QuotingBase.metadata.info["rls_policies"]["order"][0].name
        self.assertIn(" ", policy_name)
        self.assertEqual(
            self._quoting_policy_names(),
            {
                ("public", "order", policy_name),
                ("public", "MixedCase", policy_name),
                ("MixedSchema", "MixedTable", policy_name),
            },
        )
        self.assertEqual(self._quoting_table_ops(QuotingBase.metadata), [])

        # Reverse every operation to exercise disable_rls and drop_policy.
        with self.admin_engine.begin() as conn:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(conn)
            )
            for op in reversed(ops):
                operations.invoke(op.reverse())
        self.assertEqual(self._quoting_policy_names(), set())
        self.assertEqual(self._rls_flags("order"), (False, False))
        self.assertEqual(self._rls_flags("MixedTable", "MixedSchema"), (False, False))

    def test_create_policies_quotes_identifiers(self):
        """create_policies works on reserved-word and mixed-case names."""
        QuotingBase = self._make_quoting_base()
        with self.admin_engine.connect() as conn:
            conn.execute(sqlalchemy.text('CREATE SCHEMA "MixedSchema"'))
            QuotingBase.metadata.create_all(conn)
            create_policies.create_policies(QuotingBase, conn)
        self.addCleanup(self._drop_quoting_tables, QuotingBase.metadata)

        self.assertEqual(self._rls_flags("order"), (True, True))
        self.assertEqual(self._rls_flags("MixedCase"), (True, True))
        self.assertEqual(self._rls_flags("MixedTable", "MixedSchema"), (True, True))
        self.assertEqual(len(self._quoting_policy_names()), 3)
        self.assertEqual(self._quoting_table_ops(QuotingBase.metadata), [])

    def test_existing_policies_on_table_with_rls_disabled(self):
        """Autogenerate re-enables RLS without re-creating existing policies,
        and drops stale policies, when RLS has been disabled on a table."""
        self._autogenerate_and_upgrade("ensure policies exist")
        expected_names = self._policy_names("users")
        self.assertTrue(expected_names)
        with self.admin_engine.begin() as conn:
            conn.execute(
                sqlalchemy.text("ALTER TABLE users DISABLE ROW LEVEL SECURITY")
            )
            conn.execute(
                sqlalchemy.text("CREATE POLICY stale_policy ON users USING (true)")
            )
        self.assertEqual(self._rls_flags("users")[0], False)

        dropped, created = self._pending_policy_ops()
        self.assertEqual((dropped, created), (["stale_policy"], []))

        self._autogenerate_and_upgrade("re-enable rls")
        self.assertEqual(self._rls_flags("users"), (True, True))
        self.assertEqual(self._policy_names("users"), expected_names)
        self.assertEqual(self._pending_policy_ops(), ([], []))
        self.assertEqual(self._pending_enable_ops(), [])

    def test_migrating_external_policies(self):
        """Hand-written policies can be adopted as external policies, then
        rewritten as native policies one at a time."""
        self._autogenerate_and_upgrade("ensure policies exist")
        native_names = self._policy_names("items")
        with self.admin_engine.begin() as conn:
            conn.execute(
                sqlalchemy.text(
                    'CREATE POLICY "Legacy Policy" ON items FOR SELECT USING (true)'
                )
            )
        self.addCleanup(self._autogenerate_and_upgrade, "drop legacy policy")

        # Phase 1: generation is suppressed, so nothing would be dropped.
        with mock.patch.dict(os.environ, {"RLS_SUPPRESS_ALEMBIC_GENERATION": "1"}):
            self.assertEqual(self._pending_policy_ops(), ([], []))
        self.assertEqual(self._pending_policy_ops(), (["Legacy Policy"], []))

        # Phase 2: declaring the policy as external results in no diff.
        item_policies = models.Item.__rls_policies__
        original_policies = list(item_policies)
        self.addCleanup(item_policies.__setitem__, slice(None), original_policies)
        item_policies.append(policy.ExternalPolicy(name="Legacy Policy"))
        self.assertEqual(self._pending_policy_ops(), ([], []))
        self._autogenerate_and_upgrade("adopt legacy policy")
        self.assertEqual(self._policy_names("items"), native_names | {"Legacy Policy"})

        # Phase 3: rewriting the external policy as a native one replaces it.
        native = policy.Policy.from_sqla(
            expr=lambda: sqlalchemy.true(),
            condition_args=[],
            cmd=policy.Command.select,
            name="legacy",
        )
        item_policies[-1] = native
        self.assertEqual(self._pending_policy_ops(), (["Legacy Policy"], [native.name]))
        self._autogenerate_and_upgrade("rewrite legacy policy")
        self.assertEqual(self._policy_names("items"), native_names | {native.name})
        self.assertEqual(self._pending_policy_ops(), ([], []))


if __name__ == "__main__":
    unittest.main()
