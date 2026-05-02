import unittest
from unittest import mock

import sqlalchemy
from sqlalchemy import orm

from rls import create_policies


def _make_base_with_policies(rls_policies: dict) -> type[orm.DeclarativeMeta]:
    """Return a declarative base whose metadata carries the given rls_policies dict."""
    Base: type[orm.DeclarativeMeta] = orm.declarative_base()
    Base.metadata.info["rls_policies"] = rls_policies
    return Base


class TestCreatePolicies(unittest.TestCase):
    def _make_connection(self) -> mock.MagicMock:
        return mock.MagicMock()

    def test_enable_rls_not_called_for_table_with_no_policies(self):
        """ENABLE ROW LEVEL SECURITY must not be issued for a table with an empty policy list."""
        Base = _make_base_with_policies({"no_policy_table": []})
        conn = self._make_connection()

        create_policies.create_policies(Base, conn)

        executed_sqls = [str(call.args[0]) for call in conn.execute.call_args_list]
        enable_rls_calls = [s for s in executed_sqls if "ENABLE ROW LEVEL SECURITY" in s]
        self.assertEqual(
            len(enable_rls_calls),
            0,
            "Expected no ENABLE ROW LEVEL SECURITY calls for a table with no policies, "
            f"but got: {enable_rls_calls}",
        )

    def test_enable_rls_called_for_table_with_policies(self):
        """ENABLE ROW LEVEL SECURITY must be issued for a table that has at least one policy."""
        from sqlalchemy import sql

        from rls import schemas

        policy = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        Base = _make_base_with_policies({"my_table": [policy]})
        conn = self._make_connection()

        create_policies.create_policies(Base, conn)

        executed_sqls = [str(call.args[0]) for call in conn.execute.call_args_list]
        enable_rls_calls = [
            s
            for s in executed_sqls
            if "ENABLE ROW LEVEL SECURITY" in s and "my_table" in s
        ]
        self.assertEqual(
            len(enable_rls_calls),
            1,
            "Expected exactly one ENABLE ROW LEVEL SECURITY call for a table with policies.",
        )

    def test_only_tables_with_policies_are_processed(self):
        """When the dict mixes empty and non-empty policy lists, only tables with policies get ENABLE RLS."""
        from sqlalchemy import sql

        from rls import schemas

        policy = schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("id") == x,
        )
        Base = _make_base_with_policies(
            {
                "table_with_policies": [policy],
                "table_without_policies": [],
            }
        )
        conn = self._make_connection()

        create_policies.create_policies(Base, conn)

        executed_sqls = [str(call.args[0]) for call in conn.execute.call_args_list]
        enable_rls_calls = [s for s in executed_sqls if "ENABLE ROW LEVEL SECURITY" in s]
        self.assertEqual(len(enable_rls_calls), 1)
        self.assertIn("table_with_policies", enable_rls_calls[0])


if __name__ == "__main__":
    unittest.main()
