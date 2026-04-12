import unittest

import sqlalchemy
import sqlalchemy.exc
from sqlalchemy import orm

from rls import rls_session, rls_sessioner
from test import database, models


def get_pg_rls_setting(session: rls_session.RlsSession, setting_name: str) -> str:
    """Reads a PostgreSQL RLS session setting value."""
    return session.execute(
        sqlalchemy.text(f"SELECT current_setting('rls.{setting_name}', true);")
    ).scalar()


class TestRLSPolicies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.admin_engine = cls.instance.admin_engine
        cls.non_superadmin_engine = cls.instance.non_superadmin_engine
        cls.session_maker = orm.sessionmaker(
            class_=rls_session.RlsSession,
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
                    sqlalchemy.text("""
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
                    "qual": "((owner_id <= (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_greater_than_accountid_policy_select_policy_1",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id > (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((owner_id = (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id = (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((id = (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                    "with_check": "((id = (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((id = (current_setting('rls.account_id'::text, true))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
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

        rls_sess = rls_session.RlsSession(
            context=context, bind=self.non_superadmin_engine
        )

        with rls_sess.begin():
            # Test Policy on table users with SELECT where (id = account_id)
            my_user = (
                rls_sess.execute(sqlalchemy.text("SELECT * FROM users;"))
                .mappings()
                .fetchall()
            )
            self.assertEqual(len(my_user), 1, "Expected 1 user to be returned.")
            self.assertEqual(my_user[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                my_user[0]["username"], "user1", "Expected username to be 'user1'."
            )

            # Test bypassing RLS
            with rls_sess.bypass_rls():
                my_user = (
                    rls_sess.execute(sqlalchemy.text("SELECT * FROM users;"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(my_user), 2, "Expected 2 users to be returned.")

    def test_rls_query_with_rls_sessioner_and_bypass(self):
        # Concrete implementation of ContextGetter
        class ExampleContextGetter(rls_sessioner.ContextGetter):
            def get_context(self, *args, **kwargs) -> models.SampleRlsContext:
                account_id = kwargs.get("account_id", 1)
                return models.SampleRlsContext(account_id=account_id)

        my_sessioner = rls_sessioner.RlsSessioner(
            sessionmaker=self.session_maker, context_getter=ExampleContextGetter()
        )

        with my_sessioner(account_id=1) as session:
            res = (
                session.execute(sqlalchemy.text("SELECT * FROM users"))
                .mappings()
                .fetchall()
            )
            self.assertEqual(len(res), 1, "Expected 1 user to be returned.")
            self.assertEqual(res[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                res[0]["username"], "user1", "Expected username to be 'user1'."
            )

            with session.bypass_rls():
                res = session.execute(sqlalchemy.text("SELECT * FROM users")).fetchall()
                self.assertEqual(len(res), 2, "Expected 2 users to be returned.")


class TestRLSSessionBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.non_superadmin_engine = cls.instance.non_superadmin_engine

    @classmethod
    def tearDownClass(cls):
        del cls.instance

    def _new_session(self, account_id: int = 1) -> rls_session.RlsSession:
        return rls_session.RlsSession(
            context=models.SampleRlsContext(account_id=account_id),
            bind=self.non_superadmin_engine,
        )

    def test_bypass_rls_default_false(self):
        """bypass_rls pg setting is falsy before entering a bypass context."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            setting = get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        rls_sess.close()

    def test_bypass_rls_active_inside_context(self):
        """bypass_rls pg setting is 'true' while inside the bypass_rls context."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            with rls_sess.bypass_rls():
                setting = get_pg_rls_setting(rls_sess, "bypass_rls")
                self.assertEqual(setting, "true")
        rls_sess.close()

    def test_bypass_rls_restored_after_exit(self):
        """bypass_rls pg setting is restored to false after exiting the context."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            with rls_sess.bypass_rls():
                pass
            setting = get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        rls_sess.close()

    def test_exception_during_bypass_propagates(self):
        """Exceptions raised inside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            with rls_sess.begin():
                with rls_sess.bypass_rls():
                    rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        rls_sess.close()

    def test_exception_without_bypass_propagates(self):
        """Exceptions raised outside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            with rls_sess.begin():
                rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        rls_sess.close()

    def test_sql_exception_during_bypass_restores_state(self):
        """After a SQL exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            with rls_sess.begin():
                with rls_sess.bypass_rls():
                    rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        # _rls_bypass flag must be cleared regardless of exception
        self.assertFalse(rls_sess._rls_bypass)
        # A new transaction should see no bypass
        with rls_sess.begin():
            setting = get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        rls_sess.close()

    def test_python_exception_during_bypass_restores_state(self):
        """After a Python exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with self.assertRaises(ValueError):
            with rls_sess.begin():
                with rls_sess.bypass_rls():
                    raise ValueError("Test")
        self.assertFalse(rls_sess._rls_bypass)
        with rls_sess.begin():
            setting = get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        rls_sess.close()

    def test_multiple_sessions_bypass_isolated(self):
        """Bypassing RLS on one session does not affect a concurrent session."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        with rls_sess1.begin():
            with rls_sess2.begin():
                # Without bypass each session sees only its own user
                result1 = (
                    rls_sess1.execute(sqlalchemy.text("SELECT * FROM users"))
                    .mappings()
                    .fetchall()
                )
                result2 = (
                    rls_sess2.execute(sqlalchemy.text("SELECT * FROM users"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(result1), 1)
                self.assertEqual(len(result2), 1)

                # Bypass session1 only
                with rls_sess1.bypass_rls():
                    result1_bypass = (
                        rls_sess1.execute(sqlalchemy.text("SELECT * FROM users"))
                        .mappings()
                        .fetchall()
                    )
                    result2_no_bypass = (
                        rls_sess2.execute(sqlalchemy.text("SELECT * FROM users"))
                        .mappings()
                        .fetchall()
                    )
                    self.assertEqual(
                        len(result1_bypass), 2, "Bypassed session should see all users."
                    )
                    self.assertEqual(
                        len(result2_no_bypass),
                        1,
                        "Non-bypassed session should see only its account's user.",
                    )

                # After bypass exits, session1 is restricted again
                result1_after = (
                    rls_sess1.execute(sqlalchemy.text("SELECT * FROM users"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(result1_after), 1)
        rls_sess1.close()
        rls_sess2.close()

    def test_different_contexts_see_different_data(self):
        """Sessions created with different account_ids each see only their own user."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        with rls_sess1.begin():
            with rls_sess2.begin():
                result1 = (
                    rls_sess1.execute(sqlalchemy.text("SELECT * FROM users"))
                    .mappings()
                    .fetchall()
                )
                result2 = (
                    rls_sess2.execute(sqlalchemy.text("SELECT * FROM users"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(result1), 1)
                self.assertEqual(result1[0]["id"], 1)
                self.assertEqual(len(result2), 1)
                self.assertEqual(result2[0]["id"], 2)
        rls_sess1.close()
        rls_sess2.close()


if __name__ == "__main__":
    unittest.main()
