import unittest

import sqlalchemy
from sqlalchemy import sql

from rls import _sql_gen
from rls import schemas


def _make_boolean_policy(**kwargs):
    """Create a Permissive policy with a boolean custom_expr for testing."""
    defaults = {
        "condition_args": [
            schemas.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer),
        ],
        "cmd": [schemas.Command.select],
        "custom_expr": lambda x: sql.column("id") == x,
    }
    defaults.update(kwargs)
    return schemas.Permissive(**defaults)


class TestCommand(unittest.TestCase):
    def test_all_value(self):
        self.assertEqual(schemas.Command.all.value, "ALL")

    def test_select_value(self):
        self.assertEqual(schemas.Command.select.value, "SELECT")

    def test_insert_value(self):
        self.assertEqual(schemas.Command.insert.value, "INSERT")

    def test_update_value(self):
        self.assertEqual(schemas.Command.update.value, "UPDATE")

    def test_delete_value(self):
        self.assertEqual(schemas.Command.delete.value, "DELETE")

    def test_command_is_str(self):
        self.assertIsInstance(schemas.Command.select, str)
        self.assertEqual(schemas.Command.select, "SELECT")


class TestConditionArg(unittest.TestCase):
    def test_creation(self):
        arg = schemas.ConditionArg(
            comparator_name="account_id", type=sqlalchemy.Integer
        )
        self.assertEqual(arg.comparator_name, "account_id")
        self.assertEqual(arg.type, sqlalchemy.Integer)

    def test_different_type(self):
        arg = schemas.ConditionArg(comparator_name="org_name", type=sqlalchemy.String)
        self.assertEqual(arg.comparator_name, "org_name")
        self.assertEqual(arg.type, sqlalchemy.String)


class TestCompileCustomExpr(unittest.TestCase):
    def test_returns_sql_string(self):
        result = schemas.compile_custom_expr(
            table_name="users",
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            custom_expr=lambda x: sql.column("id") == x,
        )
        self.assertIsInstance(result, str)
        self.assertIn("id", result)

    def test_no_condition_args(self):
        result = schemas.compile_custom_expr(
            table_name="items",
            condition_args=None,
            custom_expr=lambda: sql.column("active") == sql.true(),
        )
        self.assertIsInstance(result, str)
        self.assertIn("active", result)

    def test_multiple_condition_args(self):
        result = schemas.compile_custom_expr(
            table_name="items",
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
                schemas.ConditionArg(comparator_name="org_id", type=sqlalchemy.Integer),
            ],
            custom_expr=lambda x, y: (
                (sql.column("owner_id") == x) & (sql.column("org_id") == y)
            ),
        )
        self.assertIsInstance(result, str)
        self.assertIn("owner_id", result)
        self.assertIn("org_id", result)

    def test_none_custom_expr_raises(self):
        with self.assertRaises(ValueError) as ctx:
            schemas.compile_custom_expr(
                table_name="users",
                condition_args=[
                    schemas.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                custom_expr=None,
            )
        self.assertIn("custom_expr", str(ctx.exception))
        self.assertIn("users", str(ctx.exception))

    def test_argument_length_mismatch_raises(self):
        with self.assertRaises(ValueError) as ctx:
            schemas.compile_custom_expr(
                table_name="users",
                condition_args=[
                    schemas.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                custom_expr=lambda: sql.column("id") == sql.literal(1),
            )
        self.assertIn("Length mismatch", str(ctx.exception))

    def test_non_boolean_expression_raises(self):
        with self.assertRaises(ValueError) as ctx:
            schemas.compile_custom_expr(
                table_name="users",
                condition_args=[
                    schemas.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                custom_expr=lambda x: x + sql.literal(1),
            )
        self.assertIn("Boolean", str(ctx.exception))

    def test_string_type_condition_arg(self):
        result = schemas.compile_custom_expr(
            table_name="users",
            condition_args=[
                schemas.ConditionArg(comparator_name="tenant", type=sqlalchemy.String),
            ],
            custom_expr=lambda x: sql.column("tenant_name") == x,
        )
        self.assertIn("tenant_name", result)

    def test_empty_condition_args_list(self):
        result = schemas.compile_custom_expr(
            table_name="items",
            condition_args=[],
            custom_expr=lambda: sql.column("active") == sql.true(),
        )
        self.assertIn("active", result)


class TestPolicyChangedChecker(unittest.TestCase):
    def _make_compiled_policy(self, **kwargs):
        policy = _make_boolean_policy(**kwargs)
        policy.get_sql_policies(table_name="users")
        return policy

    def test_matching_policies_returns_true(self):
        meta_policy = self._make_compiled_policy()

        # Simulate a DB policy: single Command, expression already has bypass_rls
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
        )
        db_policy.expression = _sql_gen.add_bypass_rls_to_expr(meta_policy.expression)
        result = schemas.policy_changed_checker(
            db_policy=db_policy, metadata_policy=meta_policy
        )
        self.assertTrue(result)

    def test_different_expression_returns_false(self):
        meta_policy = self._make_compiled_policy()
        different_policy = self._make_compiled_policy(
            custom_expr=lambda x: sql.column("id") > x,
        )

        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
        )
        db_policy.expression = _sql_gen.add_bypass_rls_to_expr(
            different_policy.expression
        )
        result = schemas.policy_changed_checker(
            db_policy=db_policy, metadata_policy=meta_policy
        )
        self.assertFalse(result)

    def test_different_definition_returns_false(self):
        meta_policy = schemas.Restrictive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        meta_policy.get_sql_policies(table_name="users")

        # DB policy has PERMISSIVE definition, but meta is RESTRICTIVE
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
        )
        db_policy.expression = _sql_gen.add_bypass_rls_to_expr(meta_policy.expression)
        result = schemas.policy_changed_checker(
            db_policy=db_policy, metadata_policy=meta_policy
        )
        self.assertFalse(result)

    def test_list_cmd_is_unwrapped(self):
        """policy_changed_checker unwraps a list cmd to a single Command for comparison."""
        meta_policy = _make_boolean_policy(
            cmd=[schemas.Command.select, schemas.Command.update],
        )
        meta_policy.get_sql_policies(table_name="users")

        # DB policy has single Command matching the first element of meta's list
        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
        )
        db_policy.expression = _sql_gen.add_bypass_rls_to_expr(meta_policy.expression)
        result = schemas.policy_changed_checker(
            db_policy=db_policy, metadata_policy=meta_policy
        )
        self.assertTrue(result)

    def test_does_not_mutate_original_policy(self):
        """policy_changed_checker should not mutate the metadata_policy passed in."""
        meta_policy = self._make_compiled_policy()
        original_expr = meta_policy.expression
        original_cmd = meta_policy.cmd

        db_policy = schemas.Policy(
            definition="PERMISSIVE",
            cmd=schemas.Command.select,
        )
        db_policy.expression = _sql_gen.add_bypass_rls_to_expr(meta_policy.expression)
        schemas.policy_changed_checker(db_policy=db_policy, metadata_policy=meta_policy)
        self.assertEqual(meta_policy.expression, original_expr)
        self.assertEqual(meta_policy.cmd, original_cmd)


class TestPolicy(unittest.TestCase):
    def test_get_sql_policies_single_cmd(self):
        policy = _make_boolean_policy(cmd=schemas.Command.select)
        results = policy.get_sql_policies(table_name="users", name_suffix="0")
        self.assertEqual(len(results), 1)
        sql_text = str(results[0])
        self.assertIn("CREATE POLICY", sql_text)
        self.assertIn("FOR SELECT", sql_text)

    def test_get_sql_policies_list_of_cmds(self):
        policy = _make_boolean_policy(
            cmd=[schemas.Command.select, schemas.Command.update],
        )
        results = policy.get_sql_policies(table_name="users", name_suffix="0")
        self.assertEqual(len(results), 2)
        self.assertIn("FOR SELECT", str(results[0]))
        self.assertIn("FOR UPDATE", str(results[1]))

    def test_get_sql_policies_custom_policy_name(self):
        policy = _make_boolean_policy(custom_policy_name="my_custom")
        policy.get_sql_policies(table_name="users", name_suffix="1")
        self.assertEqual(policy.policy_names, ["users_my_custom_select_policy_1"])

    def test_get_sql_policies_default_policy_name(self):
        policy = _make_boolean_policy(custom_policy_name=None)
        policy.get_sql_policies(table_name="users", name_suffix="0")
        self.assertEqual(policy.policy_names, ["users_permissive_select_policy_0"])

    def test_policy_names_reset_on_reinvocation(self):
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users", name_suffix="0")
        first_names = list(policy.policy_names)
        policy.get_sql_policies(table_name="users", name_suffix="1")
        self.assertNotEqual(first_names, policy.policy_names)
        self.assertEqual(len(policy.policy_names), 1)

    def test_expression_populated_after_get_sql_policies(self):
        policy = _make_boolean_policy()
        self.assertEqual(policy.expression, "")
        policy.get_sql_policies(table_name="users")
        self.assertNotEqual(policy.expression, "")
        self.assertIn("id", policy.expression)

    def test_expression_setter(self):
        policy = _make_boolean_policy()
        policy.expression = "some_expr"
        self.assertEqual(policy.expression, "some_expr")

    def test_get_sql_policies_insert_cmd(self):
        policy = _make_boolean_policy(cmd=schemas.Command.insert)
        results = policy.get_sql_policies(table_name="items")
        sql_text = str(results[0])
        self.assertIn("FOR INSERT", sql_text)
        self.assertIn("WITH CHECK", sql_text)

    def test_get_sql_policies_delete_cmd(self):
        policy = _make_boolean_policy(cmd=schemas.Command.delete)
        results = policy.get_sql_policies(table_name="items")
        sql_text = str(results[0])
        self.assertIn("FOR DELETE", sql_text)
        self.assertIn("USING", sql_text)

    def test_get_sql_policies_all_cmd(self):
        policy = _make_boolean_policy(cmd=schemas.Command.all)
        results = policy.get_sql_policies(table_name="items")
        sql_text = str(results[0])
        self.assertIn("FOR ALL", sql_text)

    def test_get_sql_policies_update_cmd(self):
        policy = _make_boolean_policy(cmd=schemas.Command.update)
        results = policy.get_sql_policies(table_name="items")
        sql_text = str(results[0])
        self.assertIn("FOR UPDATE", sql_text)
        self.assertIn("USING", sql_text)
        self.assertIn("WITH CHECK", sql_text)

    def test_get_sql_policies_no_condition_args(self):
        policy = schemas.Permissive(
            condition_args=None,
            cmd=schemas.Command.select,
            custom_expr=lambda: sql.column("active") == sql.true(),
        )
        results = policy.get_sql_policies(table_name="items")
        self.assertEqual(len(results), 1)

    def test_missing_custom_expr_raises(self):
        policy = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=schemas.Command.select,
            custom_expr=None,
        )
        with self.assertRaises(ValueError) as ctx:
            policy.get_sql_policies(table_name="users")
        self.assertIn("custom_expr", str(ctx.exception))
        self.assertIn("users", str(ctx.exception))

    def test_argument_length_mismatch_raises(self):
        policy = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=schemas.Command.select,
            custom_expr=lambda: sql.column("id") == sql.literal(1),
        )
        with self.assertRaises(ValueError) as ctx:
            policy.get_sql_policies(table_name="users")
        self.assertIn("Length mismatch", str(ctx.exception))

    def test_non_boolean_expression_raises(self):
        policy = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=schemas.Command.select,
            custom_expr=lambda x: x + sql.literal(1),
        )
        with self.assertRaises(ValueError) as ctx:
            policy.get_sql_policies(table_name="users")
        self.assertIn("Boolean", str(ctx.exception))


class TestPolicyEquality(unittest.TestCase):
    def test_equal_policies(self):
        p1 = _make_boolean_policy()
        p2 = _make_boolean_policy()
        p1.get_sql_policies(table_name="users")
        p2.get_sql_policies(table_name="users")
        self.assertEqual(p1, p2)

    def test_different_definition(self):
        p1 = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        p2 = schemas.Restrictive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        p1.get_sql_policies(table_name="users")
        p2.get_sql_policies(table_name="users")
        self.assertNotEqual(p1, p2)

    def test_different_cmd(self):
        p1 = _make_boolean_policy(cmd=[schemas.Command.select])
        p2 = _make_boolean_policy(cmd=[schemas.Command.insert])
        p1.get_sql_policies(table_name="users")
        p2.get_sql_policies(table_name="users")
        self.assertNotEqual(p1, p2)

    def test_different_expression(self):
        p1 = _make_boolean_policy(
            custom_expr=lambda x: sql.column("id") == x,
        )
        p2 = _make_boolean_policy(
            custom_expr=lambda x: sql.column("id") > x,
        )
        p1.get_sql_policies(table_name="users")
        p2.get_sql_policies(table_name="users")
        self.assertNotEqual(p1, p2)

    def test_eq_returns_not_implemented_for_non_policy(self):
        p = _make_boolean_policy()
        result = p.__eq__("not a policy")
        self.assertIs(result, NotImplemented)


class TestPolicyStr(unittest.TestCase):
    def test_str_before_compilation(self):
        policy = _make_boolean_policy()
        text = str(policy)
        self.assertIn("PERMISSIVE", text)
        self.assertIn("Policy(", text)

    def test_str_after_compilation(self):
        policy = _make_boolean_policy()
        policy.get_sql_policies(table_name="users")
        text = str(policy)
        self.assertIn("PERMISSIVE", text)
        self.assertIn("id", text)


class TestPermissive(unittest.TestCase):
    def test_definition_is_permissive(self):
        policy = _make_boolean_policy()
        self.assertEqual(policy.definition, "PERMISSIVE")

    def test_is_policy_subclass(self):
        policy = _make_boolean_policy()
        self.assertIsInstance(policy, schemas.Policy)


class TestRestrictive(unittest.TestCase):
    def test_definition_is_restrictive(self):
        policy = schemas.Restrictive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        self.assertEqual(policy.definition, "RESTRICTIVE")

    def test_is_policy_subclass(self):
        policy = schemas.Restrictive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        self.assertIsInstance(policy, schemas.Policy)

    def test_get_sql_policies_uses_restrictive(self):
        policy = schemas.Restrictive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=schemas.Command.select,
            custom_expr=lambda x: sql.column("id") == x,
        )
        results = policy.get_sql_policies(table_name="users")
        sql_text = str(results[0])
        self.assertIn("RESTRICTIVE", sql_text)


if __name__ == "__main__":
    unittest.main()
