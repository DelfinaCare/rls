import typing
import unittest
from unittest import mock

import sqlalchemy
from sqlalchemy import sql

from rls import alembic_ops
from rls import policy


def _mock_operations():
    """Return a mock Alembic operations object."""
    ops = mock.MagicMock()
    return ops


def _mock_autogen_context():
    """Return a mock autogen_context with an ``imports`` set."""
    ctx = mock.MagicMock()
    ctx.imports = set()
    return ctx


def _sample_policy(
    expr: typing.Callable[..., typing.Any] = lambda x: sql.column("id") == x,
) -> policy.Policy:
    """Create a permissive SELECT policy with a boolean expression for testing."""
    return policy.Policy.from_sqla(
        condition_args=[
            policy.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer),
        ],
        cmd=policy.Command.select,
        expr=expr,
    )


class TestCheckRlsPolicies(unittest.TestCase):
    def test_query_and_policy_mapping(self) -> None:
        for schema in (None, "myschema"):
            with self.subTest(schema=schema):
                conn = mock.MagicMock()
                conn.execute.return_value.fetchall.return_value = [
                    ("pol1", "PERMISSIVE", "SELECT", ["public"], "id = 1", None)
                ]

                policies = alembic_ops.check_rls_policies(conn, schema, "users")

                conn.execute.assert_called_once()
                query = conn.execute.call_args[0][0]
                self.assertIsInstance(query, sqlalchemy.Select)
                self.assertEqual(
                    list(query.selected_columns.keys()),
                    ["policyname", "permissive", "cmd", "roles", "qual", "with_check"],
                )
                self.assertEqual(
                    query.compile().params,
                    {"schemaname_1": schema or "public", "tablename_1": "users"},
                )
                self.assertEqual(len(policies), 1)
                self.assertEqual(policies[0].name, "pol1")
                self.assertEqual(policies[0].cmd, policy.Command.select)
                self.assertEqual(policies[0].policy_type, policy.PolicyType.permissive)
                self.assertEqual(policies[0].expr, "id = 1")


class TestEnableRlsOp(unittest.TestCase):
    def test_init_without_schema(self):
        op = alembic_ops.EnableRlsOp("users")
        self.assertEqual(op.tablename, "users")
        self.assertIsNone(op.schemaname)

    def test_init_with_schema(self):
        op = alembic_ops.EnableRlsOp("users", schemaname="myschema")
        self.assertEqual(op.tablename, "users")
        self.assertEqual(op.schemaname, "myschema")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_ops.EnableRlsOp.enable_rls(ops, "users")
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_ops.EnableRlsOp)
        self.assertEqual(invoked_op.tablename, "users")

    def test_reverse_returns_disable_op(self):
        op = alembic_ops.EnableRlsOp("users", schemaname="myschema")
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_ops.DisableRlsOp)
        self.assertEqual(rev.tablename, "users")
        self.assertEqual(rev.schemaname, "myschema")


class TestDisableRlsOp(unittest.TestCase):
    def test_init_without_schema(self):
        op = alembic_ops.DisableRlsOp("users")
        self.assertEqual(op.tablename, "users")
        self.assertIsNone(op.schemaname)

    def test_init_with_schema(self):
        op = alembic_ops.DisableRlsOp("users", schemaname="myschema")
        self.assertEqual(op.tablename, "users")
        self.assertEqual(op.schemaname, "myschema")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_ops.DisableRlsOp.disable_rls(ops, "items")
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_ops.DisableRlsOp)
        self.assertEqual(invoked_op.tablename, "items")

    def test_reverse_returns_enable_op(self):
        op = alembic_ops.DisableRlsOp("items", schemaname="s")
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_ops.EnableRlsOp)
        self.assertEqual(rev.tablename, "items")
        self.assertEqual(rev.schemaname, "s")


class TestEnableRlsImpl(unittest.TestCase):
    def test_without_schema(self):
        ops = _mock_operations()
        operation = alembic_ops.EnableRlsOp("users")
        alembic_ops.enable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE users ENABLE ROW LEVEL SECURITY"
        )

    def test_with_schema(self):
        ops = _mock_operations()
        operation = alembic_ops.EnableRlsOp("users", schemaname="myschema")
        alembic_ops.enable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE myschema.users ENABLE ROW LEVEL SECURITY"
        )


class TestDisableRlsImpl(unittest.TestCase):
    def test_without_schema(self):
        ops = _mock_operations()
        operation = alembic_ops.DisableRlsOp("users")
        alembic_ops.disable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE users DISABLE ROW LEVEL SECURITY"
        )

    def test_with_schema(self):
        ops = _mock_operations()
        operation = alembic_ops.DisableRlsOp("users", schemaname="myschema")
        alembic_ops.disable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE myschema.users DISABLE ROW LEVEL SECURITY"
        )


class TestAddRlsImports(unittest.TestCase):
    def test_adds_expected_imports(self):
        ctx = _mock_autogen_context()
        alembic_ops._add_rls_imports(ctx)
        self.assertIn("import typing", ctx.imports)
        self.assertIn("from rls import alembic_ops", ctx.imports)


class TestRenderEnableRls(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_ops.EnableRlsOp("users")
        result = alembic_ops.render_enable_rls(ctx, op)
        self.assertIn("enable_rls", result)
        self.assertIn("'users'", result)
        self.assertIn("import typing", ctx.imports)


class TestRenderDisableRls(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_ops.DisableRlsOp("items")
        result = alembic_ops.render_disable_rls(ctx, op)
        self.assertIn("disable_rls", result)
        self.assertIn("'items'", result)
        self.assertIn("import typing", ctx.imports)


class TestCreatePolicyOp(unittest.TestCase):
    def test_init(self):
        op = alembic_ops.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        self.assertEqual(op.table_name, "users")
        self.assertEqual(op.policy_name, "pol1")
        self.assertEqual(op.policy_type, "PERMISSIVE")
        self.assertEqual(op.cmd, "SELECT")
        self.assertEqual(op.expr, "id = 1")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_ops.CreatePolicyOp.create_policy(
            ops,
            table_name="users",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
            policy_name="pol1",
        )
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_ops.CreatePolicyOp)
        self.assertEqual(invoked_op.table_name, "users")
        self.assertEqual(invoked_op.policy_name, "pol1")

    def test_reverse_returns_drop_policy_op(self):
        op = alembic_ops.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_ops.DropPolicyOp)
        self.assertEqual(rev.table_name, "users")
        self.assertEqual(rev.policy_name, "pol1")
        self.assertEqual(rev.policy_type, "PERMISSIVE")
        self.assertEqual(rev.cmd, "SELECT")
        self.assertEqual(rev.expr, "id = 1")


class TestDropPolicyOp(unittest.TestCase):
    def test_init(self):
        op = alembic_ops.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        self.assertEqual(op.table_name, "users")
        self.assertEqual(op.policy_name, "pol1")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_ops.DropPolicyOp.drop_policy(
            ops,
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_ops.DropPolicyOp)
        self.assertEqual(invoked_op.table_name, "users")

    def test_reverse_returns_create_policy_op(self):
        op = alembic_ops.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_ops.CreatePolicyOp)
        self.assertEqual(rev.table_name, "users")
        self.assertEqual(rev.policy_name, "pol1")
        self.assertEqual(rev.policy_type, "PERMISSIVE")
        self.assertEqual(rev.cmd, "SELECT")
        self.assertEqual(rev.expr, "id = 1")


class TestCreatePolicyImpl(unittest.TestCase):
    def test_executes_generated_sql(self):
        ops = _mock_operations()
        operation = alembic_ops.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        alembic_ops.create_policy(ops, operation)
        ops.execute.assert_called_once()
        executed_arg = ops.execute.call_args[0][0]
        sql_text = str(executed_arg)
        self.assertIn("CREATE POLICY", sql_text)
        self.assertIn("pol1", sql_text)


class TestDropPolicyImpl(unittest.TestCase):
    def test_executes_drop_sql(self):
        ops = _mock_operations()
        operation = alembic_ops.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        alembic_ops.drop_policy(ops, operation)
        ops.execute.assert_called_once_with("DROP POLICY pol1 ON users;")


class TestRenderCreatePolicy(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_ops.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        result = alembic_ops.render_create_policy(ctx, op)
        self.assertIn("create_policy", result)
        self.assertIn("'users'", result)
        self.assertIn("'pol1'", result)
        self.assertIn("'SELECT'", result)
        self.assertIn("'PERMISSIVE'", result)
        self.assertEqual(
            result,
            "typing.cast(alembic_ops.RLSOp, op).create_policy("
            "table_name='users', policy_name='pol1', "
            "cmd='SELECT', policy_type='PERMISSIVE', expr='id = 1')",
        )
        self.assertIn("import typing", ctx.imports)


class TestRenderDropPolicy(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_ops.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            policy_type="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        result = alembic_ops.render_drop_policy(ctx, op)
        self.assertIn("drop_policy", result)
        self.assertIn("'users'", result)
        self.assertIn("'pol1'", result)
        self.assertIn("import typing", ctx.imports)


class TestCmdValue(unittest.TestCase):
    def test_with_enum(self):
        self.assertEqual(alembic_ops._cmd_value(policy.Command.select), "SELECT")

    def test_with_string(self):
        self.assertEqual(alembic_ops._cmd_value("ALL"), "ALL")


class TestCompareTableLevel(unittest.TestCase):
    """Exercise the comparator with a mocked connection (no real database)."""

    def _build_context(
        self,
        table_exists=True,
        rls_enabled=False,
        db_policies=None,
        meta_policies=None,
        tablename="users",
        schemaname=None,
    ):
        """Set up mocks for one call to compare_table_level."""
        if db_policies is None:
            db_policies = []
        if meta_policies is None:
            meta_policies = {}

        conn = mock.MagicMock()
        autogen_ctx = mock.MagicMock()
        autogen_ctx.connection = conn

        # Mock metadata_table
        metadata_table = mock.MagicMock()
        metadata_table.metadata.info = {"rls_policies": meta_policies}

        # Mock modify_ops (operations list)
        modify_ops = mock.MagicMock()
        modify_ops.ops = []

        # Patch the DB-checking helpers
        with (
            mock.patch.object(
                alembic_ops, "check_table_exists", return_value=table_exists
            ),
            mock.patch.object(
                alembic_ops, "check_rls_enabled", return_value=rls_enabled
            ),
            mock.patch.object(
                alembic_ops, "check_rls_policies", return_value=db_policies
            ),
        ):
            alembic_ops.compare_table_level(
                autogen_ctx,
                modify_ops,
                schemaname,
                tablename,
                mock.MagicMock(),  # conn_table
                metadata_table,
            )

        return modify_ops

    def test_enable_rls_when_meta_has_but_db_does_not(self):
        meta_policy = _sample_policy()
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=False,
            meta_policies={"users": [meta_policy]},
        )
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.EnableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 1)

    def test_disable_rls_when_db_has_but_meta_does_not(self):
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            meta_policies={},  # users not present => rls_enabled_meta is False
        )
        disable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.DisableRlsOp)
        ]
        self.assertEqual(len(disable_ops), 1)

    def test_no_rls_change_when_both_enabled(self):
        meta_policy = _sample_policy()
        # Simulate a matching DB policy
        db_policy = policy.Policy(
            name=meta_policy.name,
            cmd=meta_policy.cmd,
            expr=meta_policy.expr,
            policy_type=meta_policy.policy_type,
        )
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": [meta_policy]},
        )
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.EnableRlsOp)
        ]
        disable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.DisableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 0)
        self.assertEqual(len(disable_ops), 0)

    def test_creates_policy_when_missing_from_db(self):
        meta_policy = _sample_policy()
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [meta_policy]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 1)
        self.assertEqual(create_ops[0].table_name, "users")

    def test_drops_policy_when_missing_from_metadata(self):
        db_policy = policy.Policy(
            name="orphan_policy",
            cmd=policy.Command.select,
            expr="true",
            policy_type=policy.PolicyType.permissive,
        )
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": []},
        )
        drop_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.DropPolicyOp)
        ]
        self.assertEqual(len(drop_ops), 1)
        self.assertEqual(drop_ops[0].policy_name, "orphan_policy")

    def test_no_ops_when_names_match_despite_rewritten_expression(self):
        """Postgres rewrites stored expressions; matching names means no change."""
        meta_policy = _sample_policy()
        db_policy = policy.Policy(
            name=meta_policy.name,
            cmd=meta_policy.cmd,
            expr="postgres_rewritten_expression",
            policy_type=meta_policy.policy_type,
        )

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": [meta_policy]},
        )
        self.assertEqual(modify_ops.ops, [])

    def test_recreates_policy_when_changed(self):
        """A changed policy should be dropped then re-created."""
        old_policy = _sample_policy(expr=lambda x: sql.column("id") > x)
        meta_policy = _sample_policy()

        # DB policy was created from a different version of the policy, so
        # its name carries a different hash.
        db_policy = policy.Policy(
            name=old_policy.name,
            cmd=old_policy.cmd,
            expr=old_policy.expr,
            policy_type=old_policy.policy_type,
        )

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": [meta_policy]},
        )
        drop_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.DropPolicyOp)
        ]
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.CreatePolicyOp)
        ]
        self.assertEqual(len(drop_ops), 1)
        self.assertEqual(len(create_ops), 1)
        self.assertEqual(drop_ops[0].policy_name, old_policy.name)
        self.assertEqual(create_ops[0].policy_name, meta_policy.name)
        # Drops are emitted before creates.
        self.assertLess(
            modify_ops.ops.index(drop_ops[0]), modify_ops.ops.index(create_ops[0])
        )

    def test_multiple_policies_generate_multiple_create_ops(self):
        """Multiple metadata policies should each produce a separate create op."""
        policy_select = _sample_policy()
        policy_update = policy.Policy.from_sqla(
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.update,
            expr=lambda x: sql.column("id") == x,
        )
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [policy_select, policy_update]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 2)

    def test_single_cmd_creates_policy(self):
        """A policy with a single cmd should create one op."""
        meta_policy = _sample_policy()

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [meta_policy]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 1)
        self.assertEqual(create_ops[0].cmd, "SELECT")

    def test_table_not_exists_treats_rls_as_disabled(self):
        """If the table doesn't exist yet, rls_enabled_db should be False."""
        meta_policy = _sample_policy()

        modify_ops = self._build_context(
            table_exists=False,
            rls_enabled=False,
            meta_policies={"users": [meta_policy]},
        )
        # Should get an enable op since DB doesn't have RLS
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.EnableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 1)

    def test_no_enable_rls_when_table_has_empty_policies(self):
        """A table present in rls_policies with an empty list must not get ENABLE ROW LEVEL SECURITY."""
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=False,
            meta_policies={"users": []},
        )
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.EnableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 0)

    def test_disable_rls_when_table_has_empty_policies_but_rls_enabled_in_db(self):
        """When the DB has RLS enabled but the metadata has an empty policy list, DISABLE ROW LEVEL SECURITY must be issued."""
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": []},
        )
        disable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_ops.DisableRlsOp)
        ]
        self.assertEqual(len(disable_ops), 1)


if __name__ == "__main__":
    unittest.main()
