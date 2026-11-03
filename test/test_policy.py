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

    def test_type_instance(self):
        type_ = sqlalchemy.DateTime(timezone=True)
        arg = policy.ConditionArg(comparator_name="now", type=type_)
        self.assertIs(arg.type, type_)


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

    def test_casts_use_postgres_type_names(self):
        for arg_type, cast in [
            (sqlalchemy.Integer, "INTEGER"),
            (sqlalchemy.DateTime, "TIMESTAMP WITHOUT TIME ZONE"),
            (sqlalchemy.DateTime(timezone=True), "TIMESTAMP WITH TIME ZONE"),
            (sqlalchemy.Time, "TIME WITHOUT TIME ZONE"),
            (sqlalchemy.Time(timezone=True), "TIME WITH TIME ZONE"),
            (sqlalchemy.Uuid, "UUID"),
            (sqlalchemy.Interval, "INTERVAL"),
            (sqlalchemy.Enum("a", "b", name="my_enum"), "my_enum"),
        ]:
            with self.subTest(arg_type):
                result = policy.compile_sqla_expr(
                    expr=lambda x: sql.column("value") == x,
                    condition_args=[
                        policy.ConditionArg(comparator_name="value", type=arg_type),
                    ],
                    allow_bypass_rls=False,
                )
                self.assertEqual(
                    result,
                    "value = CAST(nullif(current_setting('rls.value', true), '')"
                    f" AS {cast})",
                )


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

    def test_identifiers_are_quoted(self):
        for name, table, schema, expected in (
            ("test_policy", "user", None, 'test_policy ON "user"'),
            ("test_policy", "Order", None, 'test_policy ON "Order"'),
            ("My Policy", "Docs", "MySchema", '"My Policy" ON "MySchema"."Docs"'),
            ("test_policy", "users", "myschema", "test_policy ON myschema.users"),
        ):
            with self.subTest(name=name, table=table, schema=schema):
                p = policy.Policy(name=name, cmd=policy.Command.select, expr="id = 1")
                sql_text = str(p.render_policy(table, schemaname=schema))
                self.assertIn(f"CREATE POLICY {expected} AS", sql_text)

    def test_colons_in_identifiers_are_not_bind_params(self):
        p = policy.Policy(name="a :b", cmd=policy.Command.select, expr="id = 1")
        stmt = p.render_policy("t:x")
        self.assertEqual(stmt.compile().params, {})
        self.assertIn('CREATE POLICY "a :b" ON "t:x"', str(stmt))

    def test_no_trailing_semicolon(self):
        for cmd in policy.Command:
            with self.subTest(cmd=cmd):
                sql_text = str(self._make(cmd=cmd).render_policy("users"))
                self.assertFalse(sql_text.rstrip().endswith(";"))

    def test_all_uses_using_only_without_check_expr(self):
        sql_text = str(self._make(cmd=policy.Command.all).render_policy("users"))
        self.assertTrue(sql_text.endswith("USING (id = 1)"))

    def test_update_check_expr_is_separate(self):
        for cmd in (policy.Command.update, policy.Command.all):
            with self.subTest(cmd=cmd):
                p = policy.Policy(name="p", cmd=cmd, expr="id = 1", check_expr="id = 2")
                self.assertTrue(
                    str(p.render_policy("users")).endswith(
                        "USING (id = 1) WITH CHECK (id = 2)"
                    )
                )

    def test_update_without_check_expr_checks_using_expr(self):
        sql_text = str(self._make(cmd=policy.Command.update).render_policy("users"))
        self.assertTrue(sql_text.endswith("USING (id = 1) WITH CHECK (id = 1)"))

    def test_check_expr_rejected_for_other_commands(self):
        for cmd in (
            policy.Command.select,
            policy.Command.insert,
            policy.Command.delete,
        ):
            with self.subTest(cmd=cmd), self.assertRaises(ValueError):
                policy.Policy(name="p", cmd=cmd, expr="true", check_expr="true")

    def test_roles(self):
        for roles, expected in (
            (("app",), " TO app USING"),
            (("app", "My Role"), ' TO app, "My Role" USING'),
            (("user",), ' TO "user" USING'),
            (("public",), " TO PUBLIC USING"),
            (("current_user", "SESSION_USER"), " TO CURRENT_USER, SESSION_USER USING"),
            (("a:b",), ' TO "a:b" USING'),
        ):
            with self.subTest(roles=roles):
                p = policy.Policy(name="p", expr="true", roles=roles)
                stmt = p.render_policy("users")
                self.assertEqual(stmt.compile().params, {})
                self.assertIn(f"FOR ALL{expected}", str(stmt))

    def test_no_roles_renders_no_to_clause(self):
        self.assertNotIn(" TO ", str(self._make().render_policy("users")))

    def test_empty_roles_rejected(self):
        with self.assertRaises(ValueError):
            policy.Policy(name="p", expr="true", roles=())


def _from_sqla(**kwargs) -> policy.Policy:
    return policy.Policy.from_sqla(
        expr=kwargs.pop("expr", lambda x: sql.column("id") == x),
        condition_args=[
            policy.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer)
        ],
        cmd=kwargs.pop("cmd", policy.Command.update),
        **kwargs,
    )


class TestPolicyCheckExprAndRoles(unittest.TestCase):
    def test_check_expr_is_compiled_with_condition_args(self):
        p = _from_sqla(check_expr=lambda x: sql.column("owner_id") == x)
        assert p.check_expr is not None
        self.assertIn("owner_id = CAST(", p.check_expr)
        self.assertIn("rls.account_id", p.check_expr)
        self.assertIn("rls.bypass_rls", p.check_expr)

    def test_check_expr_respects_allow_bypass_rls(self):
        p = _from_sqla(
            check_expr=lambda x: sql.column("owner_id") == x, allow_bypass_rls=False
        )
        assert p.check_expr is not None
        self.assertNotIn("bypass_rls", p.check_expr)

    def test_check_expr_and_roles_change_name(self):
        base = _from_sqla()
        with_check = _from_sqla(check_expr=lambda x: sql.column("owner_id") == x)
        with_roles = _from_sqla(roles=["app"])
        other_roles = _from_sqla(roles=["other"])
        names = {base.name, with_check.name, with_roles.name, other_roles.name}
        self.assertEqual(len(names), 4)
        for p in (with_check, with_roles, other_roles):
            self.assertTrue(p.name.startswith("permissive_account_id_update_"))

    def test_name_unchanged_without_check_expr_or_roles(self):
        """Policies that do not use the new options keep their names."""
        expected = policy._hashed_policy_name(
            "permissive_account_id_update",
            policy.PolicyType.permissive,
            policy.Command.update,
            _from_sqla().expr,
        )
        self.assertEqual(_from_sqla().name, expected)

    def test_roles_stored_as_tuple(self):
        self.assertEqual(_from_sqla(roles=["a", "b"]).roles, ("a", "b"))

    def test_string_roles_rejected(self):
        with self.assertRaises(TypeError):
            _from_sqla(roles="app")

    def test_comparator_names_recorded(self):
        self.assertEqual(_from_sqla().comparator_names, ("account_id",))


class TestConditionArgValidation(unittest.TestCase):
    def test_invalid_comparator_names_rejected(self):
        for name in ("", "account-id", "1abc", "rls.account_id", "a b", "bypass_rls"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.ConditionArg(comparator_name=name, type=sqlalchemy.Integer)

    def test_valid_comparator_names_accepted(self):
        for name in ("account_id", "_x", "AccountId2"):
            with self.subTest(name=name):
                arg = policy.ConditionArg(comparator_name=name, type=sqlalchemy.Integer)
                self.assertEqual(arg.comparator_name, name)


class TestCheckUniquePolicyNames(unittest.TestCase):
    def test_duplicates_raise(self):
        p = _from_sqla()
        with self.assertRaisesRegex(ValueError, p.name):
            policy.check_unique_policy_names("t", [p, _from_sqla()])

    def test_external_policy_name_collision_raises(self):
        p = _from_sqla()
        with self.assertRaises(ValueError):
            policy.check_unique_policy_names(
                "t", [p, policy.ExternalPolicy(name=p.name)]
            )

    def test_unique_names_pass(self):
        policy.check_unique_policy_names(
            "t", [_from_sqla(), _from_sqla(cmd=policy.Command.select)]
        )


if __name__ == "__main__":
    unittest.main()
