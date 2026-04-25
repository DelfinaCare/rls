import typing
import unittest
from unittest import mock

import sqlalchemy
from sqlalchemy import sql
from sqlalchemy.ext import declarative

from rls import alembic_rls
from rls import schemas

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_operations():
    """Return a mock Alembic operations object."""
    ops = mock.MagicMock()
    return ops


def _mock_autogen_context():
    """Return a mock autogen_context with an ``imports`` set."""
    ctx = mock.MagicMock()
    ctx.imports = set()
    return ctx


def _make_boolean_policy(**kwargs):
    """Create a Permissive policy with a boolean custom_expr for testing."""
    defaults: dict[str, typing.Any] = {
        "condition_args": [
            schemas.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer),
        ],
        "cmd": [schemas.Command.select],
        "custom_expr": lambda x: sql.column("id") == x,
    }
    defaults.update(kwargs)
    return schemas.Permissive(**defaults)


# ---------------------------------------------------------------------------
# EnableRlsOp
# ---------------------------------------------------------------------------


class TestEnableRlsOp(unittest.TestCase):
    def test_init_without_schema(self):
        op = alembic_rls.EnableRlsOp("users")
        self.assertEqual(op.tablename, "users")
        self.assertIsNone(op.schemaname)

    def test_init_with_schema(self):
        op = alembic_rls.EnableRlsOp("users", schemaname="myschema")
        self.assertEqual(op.tablename, "users")
        self.assertEqual(op.schemaname, "myschema")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_rls.EnableRlsOp.enable_rls(ops, "users")
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_rls.EnableRlsOp)
        self.assertEqual(invoked_op.tablename, "users")

    def test_reverse_returns_disable_op(self):
        op = alembic_rls.EnableRlsOp("users", schemaname="myschema")
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_rls.DisableRlsOp)
        self.assertEqual(rev.tablename, "users")
        self.assertEqual(rev.schemaname, "myschema")


# ---------------------------------------------------------------------------
# DisableRlsOp
# ---------------------------------------------------------------------------


class TestDisableRlsOp(unittest.TestCase):
    def test_init_without_schema(self):
        op = alembic_rls.DisableRlsOp("users")
        self.assertEqual(op.tablename, "users")
        self.assertIsNone(op.schemaname)

    def test_init_with_schema(self):
        op = alembic_rls.DisableRlsOp("users", schemaname="myschema")
        self.assertEqual(op.tablename, "users")
        self.assertEqual(op.schemaname, "myschema")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_rls.DisableRlsOp.disable_rls(ops, "items")
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_rls.DisableRlsOp)
        self.assertEqual(invoked_op.tablename, "items")

    def test_reverse_returns_enable_op(self):
        op = alembic_rls.DisableRlsOp("items", schemaname="s")
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_rls.EnableRlsOp)
        self.assertEqual(rev.tablename, "items")
        self.assertEqual(rev.schemaname, "s")


# ---------------------------------------------------------------------------
# enable_rls / disable_rls implementations
# ---------------------------------------------------------------------------


class TestEnableRlsImpl(unittest.TestCase):
    def test_without_schema(self):
        ops = _mock_operations()
        operation = alembic_rls.EnableRlsOp("users")
        alembic_rls.enable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE users ENABLE ROW LEVEL SECURITY"
        )

    def test_with_schema(self):
        ops = _mock_operations()
        operation = alembic_rls.EnableRlsOp("users", schemaname="myschema")
        alembic_rls.enable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE myschema.users ENABLE ROW LEVEL SECURITY"
        )


class TestDisableRlsImpl(unittest.TestCase):
    def test_without_schema(self):
        ops = _mock_operations()
        operation = alembic_rls.DisableRlsOp("users")
        alembic_rls.disable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE users DISABLE ROW LEVEL SECURITY"
        )

    def test_with_schema(self):
        ops = _mock_operations()
        operation = alembic_rls.DisableRlsOp("users", schemaname="myschema")
        alembic_rls.disable_rls(ops, operation)
        ops.execute.assert_called_once_with(
            "ALTER TABLE myschema.users DISABLE ROW LEVEL SECURITY"
        )


# ---------------------------------------------------------------------------
# _add_rls_imports
# ---------------------------------------------------------------------------


class TestAddRlsImports(unittest.TestCase):
    def test_adds_expected_imports(self):
        ctx = _mock_autogen_context()
        alembic_rls._add_rls_imports(ctx)
        self.assertIn("import typing", ctx.imports)
        self.assertIn("from rls import alembic_rls", ctx.imports)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


class TestRenderEnableRls(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_rls.EnableRlsOp("users")
        result = alembic_rls.render_enable_rls(ctx, op)
        self.assertIn("enable_rls", result)
        self.assertIn("'users'", result)
        self.assertIn("import typing", ctx.imports)


class TestRenderDisableRls(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_rls.DisableRlsOp("items")
        result = alembic_rls.render_disable_rls(ctx, op)
        self.assertIn("disable_rls", result)
        self.assertIn("'items'", result)
        self.assertIn("import typing", ctx.imports)


# ---------------------------------------------------------------------------
# CreatePolicyOp
# ---------------------------------------------------------------------------


class TestCreatePolicyOp(unittest.TestCase):
    def test_init(self):
        op = alembic_rls.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        self.assertEqual(op.table_name, "users")
        self.assertEqual(op.policy_name, "pol1")
        self.assertEqual(op.definition, "PERMISSIVE")
        self.assertEqual(op.cmd, "SELECT")
        self.assertEqual(op.expr, "id = 1")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_rls.CreatePolicyOp.create_policy(
            ops,
            table_name="users",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
            policy_name="pol1",
        )
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_rls.CreatePolicyOp)
        self.assertEqual(invoked_op.table_name, "users")
        self.assertEqual(invoked_op.policy_name, "pol1")

    def test_reverse_returns_drop_policy_op(self):
        op = alembic_rls.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_rls.DropPolicyOp)
        self.assertEqual(rev.table_name, "users")
        self.assertEqual(rev.policy_name, "pol1")
        self.assertEqual(rev.definition, "PERMISSIVE")
        self.assertEqual(rev.cmd, "SELECT")
        self.assertEqual(rev.expr, "id = 1")


# ---------------------------------------------------------------------------
# DropPolicyOp
# ---------------------------------------------------------------------------


class TestDropPolicyOp(unittest.TestCase):
    def test_init(self):
        op = alembic_rls.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        self.assertEqual(op.table_name, "users")
        self.assertEqual(op.policy_name, "pol1")

    def test_classmethod_invokes_operation(self):
        ops = _mock_operations()
        alembic_rls.DropPolicyOp.drop_policy(
            ops,
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        ops.invoke.assert_called_once()
        invoked_op = ops.invoke.call_args[0][0]
        self.assertIsInstance(invoked_op, alembic_rls.DropPolicyOp)
        self.assertEqual(invoked_op.table_name, "users")

    def test_reverse_returns_create_policy_op(self):
        op = alembic_rls.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        rev = op.reverse()
        self.assertIsInstance(rev, alembic_rls.CreatePolicyOp)
        self.assertEqual(rev.table_name, "users")
        self.assertEqual(rev.policy_name, "pol1")
        self.assertEqual(rev.definition, "PERMISSIVE")
        self.assertEqual(rev.cmd, "SELECT")
        self.assertEqual(rev.expr, "id = 1")


# ---------------------------------------------------------------------------
# create_policy / drop_policy implementations
# ---------------------------------------------------------------------------


class TestCreatePolicyImpl(unittest.TestCase):
    def test_executes_generated_sql(self):
        ops = _mock_operations()
        operation = alembic_rls.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        alembic_rls.create_policy(ops, operation)
        ops.execute.assert_called_once()
        executed_arg = ops.execute.call_args[0][0]
        sql_text = str(executed_arg)
        self.assertIn("CREATE POLICY", sql_text)
        self.assertIn("pol1", sql_text)


class TestDropPolicyImpl(unittest.TestCase):
    def test_executes_drop_sql(self):
        ops = _mock_operations()
        operation = alembic_rls.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        alembic_rls.drop_policy(ops, operation)
        ops.execute.assert_called_once_with("DROP POLICY pol1 ON users;")


# ---------------------------------------------------------------------------
# render_create_policy / render_drop_policy
# ---------------------------------------------------------------------------


class TestRenderCreatePolicy(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_rls.CreatePolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        result = alembic_rls.render_create_policy(ctx, op)
        self.assertIn("create_policy", result)
        self.assertIn("'users'", result)
        self.assertIn("'pol1'", result)
        self.assertIn("'SELECT'", result)
        self.assertIn("'PERMISSIVE'", result)
        self.assertIn("import typing", ctx.imports)


class TestRenderDropPolicy(unittest.TestCase):
    def test_output(self):
        ctx = _mock_autogen_context()
        op = alembic_rls.DropPolicyOp(
            table_name="users",
            policy_name="pol1",
            definition="PERMISSIVE",
            cmd="SELECT",
            expr="id = 1",
        )
        result = alembic_rls.render_drop_policy(ctx, op)
        self.assertIn("drop_policy", result)
        self.assertIn("'users'", result)
        self.assertIn("'pol1'", result)
        self.assertIn("import typing", ctx.imports)


# ---------------------------------------------------------------------------
# _cmd_value
# ---------------------------------------------------------------------------


class TestCmdValue(unittest.TestCase):
    def test_with_enum(self):
        self.assertEqual(alembic_rls._cmd_value(schemas.Command.select), "SELECT")

    def test_with_string(self):
        self.assertEqual(alembic_rls._cmd_value("ALL"), "ALL")


# ---------------------------------------------------------------------------
# set_metadata_info
# ---------------------------------------------------------------------------


class TestSetMetadataInfo(unittest.TestCase):
    def test_populates_rls_policies(self):
        from test import models

        Base = models.Base
        # set_metadata_info is already called by register_rls, but we call it
        # explicitly to verify the behavior.
        result = alembic_rls.set_metadata_info(Base)
        self.assertIs(result, Base)
        self.assertIn("rls_policies", Base.metadata.info)
        self.assertIn("users", Base.metadata.info["rls_policies"])
        self.assertIn("items", Base.metadata.info["rls_policies"])

    def test_skips_models_without_rls_policies(self):
        """Models without __rls_policies__ should not appear in the dict."""
        Base: typing.Any = declarative.declarative_base()

        class NoRls(Base):
            __tablename__ = "no_rls"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        alembic_rls.set_metadata_info(Base)
        self.assertEqual(Base.metadata.info["rls_policies"], {})


# ---------------------------------------------------------------------------
# compare_table_level  (the autogenerate comparator)
# ---------------------------------------------------------------------------


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
                alembic_rls, "check_table_exists", return_value=table_exists
            ),
            mock.patch.object(
                alembic_rls, "check_rls_enabled", return_value=rls_enabled
            ),
            mock.patch.object(
                alembic_rls, "check_rls_policies", return_value=db_policies
            ),
        ):
            alembic_rls.compare_table_level(
                autogen_ctx,
                modify_ops,
                schemaname,
                tablename,
                mock.MagicMock(),  # conn_table
                metadata_table,
            )

        return modify_ops

    # -- RLS enable/disable -------------------------------------------------

    def test_enable_rls_when_meta_has_but_db_does_not(self):
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=False,
            meta_policies={"users": [policy]},
        )
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.EnableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 1)

    def test_disable_rls_when_db_has_but_meta_does_not(self):
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            meta_policies={},  # users not present => rls_enabled_meta is False
        )
        disable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.DisableRlsOp)
        ]
        self.assertEqual(len(disable_ops), 1)

    def test_no_rls_change_when_both_enabled(self):
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")
        # Simulate a matching DB policy
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
            custom_policy_name=policy.policy_names[0],
        )
        db_policy.expression = policy.expression
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": [policy]},
        )
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.EnableRlsOp)
        ]
        disable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.DisableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 0)
        self.assertEqual(len(disable_ops), 0)

    # -- Policy create/drop -------------------------------------------------

    def test_creates_policy_when_missing_from_db(self):
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [policy]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 1)
        self.assertEqual(create_ops[0].table_name, "users")

    def test_drops_policy_when_missing_from_metadata(self):
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
            custom_policy_name="orphan_policy",
        )
        db_policy.expression = "true"
        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": []},
        )
        drop_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.DropPolicyOp)
        ]
        self.assertEqual(len(drop_ops), 1)
        self.assertEqual(drop_ops[0].policy_name, "orphan_policy")

    def test_recreates_policy_when_changed(self):
        """A changed policy should be dropped then re-created."""
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")

        # DB policy has same name but different expression
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
            custom_policy_name=policy.policy_names[0],
        )
        db_policy.expression = "totally_different_expression"

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[db_policy],
            meta_policies={"users": [policy]},
        )
        drop_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.DropPolicyOp)
        ]
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.CreatePolicyOp)
        ]
        self.assertGreaterEqual(len(drop_ops), 1)
        self.assertGreaterEqual(len(create_ops), 1)

    def test_list_cmd_generates_multiple_policies(self):
        """A policy with cmd=[SELECT, UPDATE] should produce two create ops."""
        policy = _make_boolean_policy(
            cmd=[schemas.Command.select, schemas.Command.update],
        )
        policy.get_sql_policies(table_name="users")

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [policy]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 2)

    def test_single_cmd_creates_policy(self):
        """A policy with a single (non-list) cmd should still create one op."""
        policy = _make_boolean_policy(cmd=schemas.Command.select)
        policy.get_sql_policies(table_name="users")

        modify_ops = self._build_context(
            table_exists=True,
            rls_enabled=True,
            db_policies=[],
            meta_policies={"users": [policy]},
        )
        create_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.CreatePolicyOp)
        ]
        self.assertEqual(len(create_ops), 1)
        self.assertEqual(create_ops[0].cmd, "SELECT")

    def test_table_not_exists_treats_rls_as_disabled(self):
        """If the table doesn't exist yet, rls_enabled_db should be False."""
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")

        modify_ops = self._build_context(
            table_exists=False,
            rls_enabled=False,
            meta_policies={"users": [policy]},
        )
        # Should get an enable op since DB doesn't have RLS
        enable_ops = [
            op for op in modify_ops.ops if isinstance(op, alembic_rls.EnableRlsOp)
        ]
        self.assertEqual(len(enable_ops), 1)


if __name__ == "__main__":
    unittest.main()
