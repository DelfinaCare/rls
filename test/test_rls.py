import unittest

from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from rls.rls_session import RlsSession
from rls.rls_sessioner import ContextGetter, RlsSessioner
from test import database, models


class TestRLSPolicies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.admin_engine = cls.instance.admin_engine
        cls.non_superadmin_engine = cls.instance.non_superadmin_engine
        cls.session_maker = sessionmaker(
            class_=RlsSession,
            autoflush=False,
            autocommit=False,
            bind=cls.instance.non_superadmin_engine,
        )

    @classmethod
    def tearDownClass(cls):
        del cls.instance

    def test_policy_creation(self):
        # Check that RLS policies exist in the database
        with self.admin_engine.connect() as session:
            # We checked for two tables at once because tablename is auto applied to policy name so we don't have to check separately
            policies = (
                session.execute(
                    text("""
                SELECT policyname, permissive, qual, with_check, cmd
                FROM pg_policies
                WHERE tablename IN ('items', 'users');
            """)
                )
                .mappings()
                .fetchall()
            )

            self.assertEqual(
                len(policies),
                6,
                "Expected 6 RLS policies to be applied to users and items tables.",
            )
            expected_policies = [
                {
                    "policyname": "items_smaller_than_or_equal_accountid_policy_all_policy_2",
                    "permissive": "PERMISSIVE",
                    "cmd": "ALL",
                    "qual": "((owner_id <= (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_greater_than_accountid_policy_select_policy_1",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id > (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                    "with_check": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
            ]

            for policy in expected_policies:
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

    def test_rls_query_with_rls_session_and_bypass(self):
        context = models.SampleRlsContext(account_id=1)

        rls_session = RlsSession(context=context, bind=self.non_superadmin_engine)

        with rls_session.begin():
            # Test Policy on table users with SELECT where (id = account_id)
            my_user = (
                rls_session.execute(text("SELECT * FROM users;")).mappings().fetchall()
            )
            self.assertEqual(len(my_user), 1, "Expected 1 user to be returned.")
            self.assertEqual(my_user[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                my_user[0]["username"], "user1", "Expected username to be 'user1'."
            )

            # Test bypassing RLS
            with rls_session.bypass_rls():
                my_user = (
                    rls_session.execute(text("SELECT * FROM users;"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(my_user), 2, "Expected 2 users to be returned.")

    def test_rls_query_with_rls_sessioner_and_bypass(self):
        # Concrete implementation of ContextGetter
        class ExampleContextGetter(ContextGetter):
            def get_context(self, *args, **kwargs) -> models.SampleRlsContext:
                account_id = kwargs.get("account_id", 1)
                return models.SampleRlsContext(account_id=account_id)

        my_sessioner = RlsSessioner(
            sessionmaker=self.session_maker, context_getter=ExampleContextGetter()
        )

        with my_sessioner(account_id=1) as session:
            res = session.execute(text("SELECT * FROM users")).mappings().fetchall()
            self.assertEqual(len(res), 1, "Expected 1 user to be returned.")
            self.assertEqual(res[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                res[0]["username"], "user1", "Expected username to be 'user1'."
            )

            with session.bypass_rls():
                res = session.execute(text("SELECT * FROM users")).fetchall()
                self.assertEqual(len(res), 2, "Expected 2 users to be returned.")


if __name__ == "__main__":
    unittest.main()
