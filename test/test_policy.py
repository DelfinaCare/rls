import unittest

import sqlalchemy
from sqlalchemy import sql

from rls import policy


class TestCommand(unittest.TestCase):
    def test_all_value(self):
        self.assertEqual(policy.Command.all.value, "ALL")

    def test_select_value(self):
        self.assertEqual(policy.Command.select.value, "SELECT")

    def test_insert_value(self):
        self.assertEqual(policy.Command.insert.value, "INSERT")

    def test_update_value(self):
        self.assertEqual(policy.Command.update.value, "UPDATE")

    def test_delete_value(self):
        self.assertEqual(policy.Command.delete.value, "DELETE")

    def test_command_is_str(self):
        self.assertIsInstance(policy.Command.select, str)
        self.assertEqual(policy.Command.select, "SELECT")


class TestPolicyType(unittest.TestCase):
    def test_permissive_value(self):
        self.assertEqual(policy.PolicyType.permissive.value, "PERMISSIVE")

    def test_restrictive_value(self):
        self.assertEqual(policy.PolicyType.restrictive.value, "RESTRICTIVE")

    def test_policy_type_is_str(self):
        self.assertIsInstance(policy.PolicyType.permissive, str)
        self.assertEqual(policy.PolicyType.permissive, "PERMISSIVE")


class TestConditionArg(unittest.TestCase):
    def test_creation(self):
        arg = policy.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer)
        self.assertEqual(arg.comparator_name, "account_id")
        self.assertEqual(arg.type, sqlalchemy.Integer)

    def test_different_type(self):
        arg = policy.ConditionArg(comparator_name="org_name", type=sqlalchemy.String)
        self.assertEqual(arg.comparator_name, "org_name")
        self.assertEqual(arg.type, sqlalchemy.String)


class TestCompileSqlaExpr(unittest.TestCase):
    def test_returns_sql_string(self):
        result = policy.compile_sqla_expr(
            expr=lambda x: sql.column("id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
        )
        self.assertIsInstance(result, str)
        self.assertIn("id", result)

    def test_no_condition_args(self):
        result = policy.compile_sqla_expr(
            expr=lambda: sql.column("active") == sql.true(),
            condition_args=None,
        )
        self.assertIsInstance(result, str)
        self.assertIn("active", result)

    def test_multiple_condition_args(self):
        result = policy.compile_sqla_expr(
            expr=lambda x, y: (
                (sql.column("owner_id") == x) & (sql.column("org_id") == y)
            ),
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
                policy.ConditionArg(comparator_name="org_id", type=sqlalchemy.Integer),
            ],
        )
        self.assertIsInstance(result, str)
        self.assertIn("owner_id", result)
        self.assertIn("org_id", result)

    def test_argument_length_mismatch_raises(self):
        with self.assertRaises(ValueError) as ctx:
            policy.compile_sqla_expr(
                expr=lambda: sql.column("id") == sql.literal(1),
                condition_args=[
                    policy.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
            )
        self.assertIn("Length mismatch", str(ctx.exception))

    def test_non_boolean_expression_raises(self):
        with self.assertRaises(TypeError) as ctx:
            policy.compile_sqla_expr(
                expr=lambda x: x + sql.literal(1),
                condition_args=[
                    policy.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
            )
        self.assertIn("Boolean", str(ctx.exception))

    def test_string_type_condition_arg(self):
        result = policy.compile_sqla_expr(
            expr=lambda x: sql.column("tenant_name") == x,
            condition_args=[
                policy.ConditionArg(comparator_name="tenant", type=sqlalchemy.String),
            ],
        )
        self.assertIn("tenant_name", result)

    def test_empty_condition_args_list(self):
        result = policy.compile_sqla_expr(
            expr=lambda: sql.column("active") == sql.true(),
            condition_args=[],
        )
        self.assertIn("active", result)

    def test_bypass_rls_included_by_default(self):
        result = policy.compile_sqla_expr(
            expr=lambda x: sql.column("id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
        )
        self.assertIn("bypass_rls", result)

    def test_bypass_rls_excluded_when_false(self):
        result = policy.compile_sqla_expr(
            expr=lambda x: sql.column("id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            allow_bypass_rls=False,
        )
        self.assertNotIn("bypass_rls", result)


class TestPolicyFromSqla(unittest.TestCase):
    def _make(self, **kwargs):
        defaults = {
            "expr": lambda x: sql.column("id") == x,
            "condition_args": [
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            "cmd": policy.Command.select,
        }
        defaults.update(kwargs)
        return policy.Policy.from_sqla(**defaults)

    def test_expr_is_string(self):
        p = self._make()
        self.assertIsInstance(p.expr, str)
        self.assertIn("id", p.expr)

    def test_cmd_stored(self):
        p = self._make(cmd=policy.Command.select)
        self.assertEqual(p.cmd, policy.Command.select)

    def test_policy_type_defaults_to_permissive(self):
        p = self._make()
        self.assertEqual(p.policy_type, policy.PolicyType.permissive)

    def test_policy_type_restrictive(self):
        p = self._make(policy_type=policy.PolicyType.restrictive)
        self.assertEqual(p.policy_type, policy.PolicyType.restrictive)

    def test_name_is_lowercase(self):
        p = self._make()
        self.assertEqual(p.name, p.name.lower())

    def test_name_auto_generated(self):
        p = self._make()
        self.assertIsNotNone(p.name)
        self.assertGreater(len(p.name), 0)

    def test_auto_generated_name_format(self):
        p = self._make()
        self.assertRegex(p.name, r"^permissive_account_id_select_[0-9a-z]{8}$")

    def test_explicit_name_used_as_prefix(self):
        p = self._make(name="My_Policy")
        self.assertRegex(p.name, r"^my_policy_[0-9a-z]{8}$")

    def test_bypass_rls_in_expr_by_default(self):
        p = self._make()
        self.assertIn("bypass_rls", p.expr)

    def test_bypass_rls_excluded_when_false(self):
        p = self._make(allow_bypass_rls=False)
        self.assertNotIn("bypass_rls", p.expr)

    def test_same_exprs_produce_same_name(self):
        p1 = self._make()
        p2 = self._make()
        self.assertEqual(p1.name, p2.name)

    def test_different_exprs_produce_different_names(self):
        p1 = self._make(expr=lambda x: sql.column("id") == x)
        p2 = self._make(expr=lambda x: sql.column("id") > x)
        self.assertNotEqual(p1.name, p2.name)

    def test_name_changes_when_bypass_changes(self):
        p1 = self._make()
        p2 = self._make(allow_bypass_rls=False)
        self.assertNotEqual(p1.name, p2.name)

    def test_name_changes_when_cmd_changes_with_explicit_name(self):
        p1 = self._make(name="p", cmd=policy.Command.select)
        p2 = self._make(name="p", cmd=policy.Command.update)
        self.assertNotEqual(p1.name, p2.name)

    def test_name_changes_when_policy_type_changes_with_explicit_name(self):
        p1 = self._make(name="p")
        p2 = self._make(name="p", policy_type=policy.PolicyType.restrictive)
        self.assertNotEqual(p1.name, p2.name)

    def test_name_changes_when_expr_changes_with_explicit_name(self):
        p1 = self._make(name="p", expr=lambda x: sql.column("id") == x)
        p2 = self._make(name="p", expr=lambda x: sql.column("id") > x)
        self.assertNotEqual(p1.name, p2.name)

    def test_long_name_fits_postgres_identifier_limit(self):
        p = self._make(name="x" * 100)
        self.assertLessEqual(len(p.name.encode("utf-8")), 63)
        self.assertRegex(p.name, r"_[0-9a-z]{8}$")


class TestHashedPolicyName(unittest.TestCase):
    def _name(self, **kwargs):
        args = {
            "base_name": "p",
            "policy_type": policy.PolicyType.permissive,
            "cmd": policy.Command.select,
            "expr": "true",
        }
        args.update(kwargs)
        return policy._hashed_policy_name(**args)

    def test_stable_for_same_content(self):
        self.assertEqual(self._name(), self._name())

    def test_changes_with_expr(self):
        self.assertNotEqual(self._name(), self._name(expr="false"))

    def test_changes_with_cmd(self):
        self.assertNotEqual(self._name(), self._name(cmd=policy.Command.update))

    def test_changes_with_policy_type(self):
        self.assertNotEqual(
            self._name(), self._name(policy_type=policy.PolicyType.restrictive)
        )


class TestPolicyRenderPolicy(unittest.TestCase):
    def _make(
        self, cmd=policy.Command.select, policy_type=policy.PolicyType.permissive
    ):
        return policy.Policy(
            name="test_policy",
            cmd=cmd,
            expr="id = 1",
            policy_type=policy_type,
        )

    def test_select_uses_using(self):
        p = self._make(cmd=policy.Command.select)
        sql_text = str(p.render_policy("users"))
        self.assertIn("CREATE POLICY", sql_text)
        self.assertIn("FOR SELECT", sql_text)
        self.assertIn("USING", sql_text)
        self.assertNotIn("WITH CHECK", sql_text)

    def test_delete_uses_using(self):
        p = self._make(cmd=policy.Command.delete)
        sql_text = str(p.render_policy("users"))
        self.assertIn("FOR DELETE", sql_text)
        self.assertIn("USING", sql_text)

    def test_all_uses_using(self):
        p = self._make(cmd=policy.Command.all)
        sql_text = str(p.render_policy("users"))
        self.assertIn("FOR ALL", sql_text)
        self.assertIn("USING", sql_text)

    def test_insert_uses_with_check_only(self):
        p = self._make(cmd=policy.Command.insert)
        sql_text = str(p.render_policy("users"))
        self.assertIn("FOR INSERT", sql_text)
        self.assertIn("WITH CHECK", sql_text)
        self.assertNotIn("USING", sql_text)

    def test_update_uses_using_and_with_check(self):
        p = self._make(cmd=policy.Command.update)
        sql_text = str(p.render_policy("users"))
        self.assertIn("FOR UPDATE", sql_text)
        self.assertIn("USING", sql_text)
        self.assertIn("WITH CHECK", sql_text)

    def test_policy_name_in_output(self):
        p = self._make()
        sql_text = str(p.render_policy("users"))
        self.assertIn("test_policy", sql_text)

    def test_table_name_in_output(self):
        p = self._make()
        sql_text = str(p.render_policy("my_table"))
        self.assertIn("my_table", sql_text)

    def test_permissive_in_output(self):
        p = self._make(policy_type=policy.PolicyType.permissive)
        sql_text = str(p.render_policy("users"))
        self.assertIn("PERMISSIVE", sql_text)

    def test_restrictive_in_output(self):
        p = self._make(policy_type=policy.PolicyType.restrictive)
        sql_text = str(p.render_policy("users"))
        self.assertIn("RESTRICTIVE", sql_text)


if __name__ == "__main__":
    unittest.main()
