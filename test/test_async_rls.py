import unittest

import pydantic
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import rls_session
from test import database
from test import models

_MALICIOUS_CONTEXT_VALUE = "foo; DROP SCHEMA IF EXISTS PUBLIC CASCADE;"
_USER_ID_QUERY = sqlalchemy.text("SELECT id FROM users ORDER BY id ASC")


async def get_pg_rls_setting(
    session: rls_session.AsyncRlsSession, setting_name: str
) -> str:
    """Reads a PostgreSQL RLS session setting value."""
    result = await session.execute(
        sqlalchemy.text(f"SELECT current_setting('rls.{setting_name}', true);")
    )
    return result.scalar()


class TestAsyncRLSPolicies(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()

    @classmethod
    def tearDownClass(cls):
        cls.instance.close()

    def _async_engine(self) -> sa_asyncio.AsyncEngine:
        return self.instance.async_non_superadmin_engine

    async def test_rls_query_with_async_rls_session(self):
        """AsyncRlsSession applies RLS and returns only the matching user."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(
            context=context, bind=self._async_engine()
        )
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])

    async def test_rls_query_with_async_rls_session_and_bypass(self):
        """AsyncRlsSession with bypass_rls returns all users."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(
            context=context, bind=self._async_engine()
        )
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(result, [1, 2])


class TestAsyncRLSSessionBehavior(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()

    @classmethod
    def tearDownClass(cls):
        cls.instance.close()

    def _new_session(self, account_id: int = 1) -> rls_session.AsyncRlsSession:
        return rls_session.AsyncRlsSession(
            context=models.SampleRlsContext(account_id=account_id),
            bind=self.instance.async_non_superadmin_engine,
        )

    async def test_bypass_rls_default_false(self):
        """bypass_rls pg setting is falsy before entering a bypass context."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        await rls_sess.close()

    async def test_bypass_rls_active_inside_context(self):
        """bypass_rls pg setting is 'true' while inside the bypass_rls context."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
                self.assertEqual(setting, "true")
        await rls_sess.close()

    async def test_bypass_rls_restored_after_exit(self):
        """bypass_rls pg setting is restored to false after exiting the context."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                pass
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        await rls_sess.close()

    async def test_exception_during_bypass_propagates(self):
        """Exceptions raised inside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        await rls_sess.close()

    async def test_exception_without_bypass_propagates(self):
        """Exceptions raised outside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        await rls_sess.close()

    async def test_sql_exception_during_bypass_restores_state(self):
        """After a SQL exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        # _rls_bypass flag must be cleared regardless of exception
        self.assertFalse(rls_sess._rls_bypass)
        # A new transaction should see no bypass
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        await rls_sess.close()

    async def test_nested_bypass_rls(self):
        """Nested bypass_rls contexts maintain bypass until all contexts exit."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                self.assertEqual(
                    await get_pg_rls_setting(rls_sess, "bypass_rls"), "true"
                )
                async with rls_sess.bypass_rls():
                    self.assertEqual(
                        await get_pg_rls_setting(rls_sess, "bypass_rls"), "true"
                    )
                self.assertEqual(
                    await get_pg_rls_setting(rls_sess, "bypass_rls"), "true"
                )
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        await rls_sess.close()

    async def test_python_exception_during_bypass_restores_state(self):
        """After a Python exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with self.assertRaises(ValueError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    raise ValueError("Test")
        self.assertFalse(rls_sess._rls_bypass)
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            self.assertIn(setting, {"", None, "false"})
        await rls_sess.close()

    async def test_none_context_field_clears_rls_setting(self):
        """A nullable pydantic field set to None resets the corresponding RLS pg setting."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = rls_session.AsyncRlsSession(
            context=context, bind=self.instance.async_non_superadmin_engine
        )
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "account_id")
            self.assertEqual(
                setting,
                "",
                "RLS setting for a None context field must be reset to empty string.",
            )
        await rls_sess.close()

    async def test_none_context_field_filters_results(self):
        """A nullable pydantic field set to None returns no rows."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = rls_session.AsyncRlsSession(
            context=context, bind=self.instance.async_non_superadmin_engine
        )
        async with rls_sess.begin():
            rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(rows, [], "Expected no rows when account_id is None.")
        await rls_sess.close()

    async def test_different_contexts_see_different_data(self):
        """Sessions created with different account_ids each see only their own user."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        async with rls_sess1.begin():
            async with rls_sess2.begin():
                result1 = list((await rls_sess1.execute(_USER_ID_QUERY)).scalars())
                result2 = list((await rls_sess2.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(result1, [1])
                self.assertEqual(result2, [2])
        await rls_sess1.close()
        await rls_sess2.close()

    async def test_multiple_sessions_bypass_isolated(self):
        """Bypassing RLS on one async session does not affect a concurrent session."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        async with rls_sess1.begin():
            async with rls_sess2.begin():
                # Without bypass each session sees only its own user
                result1 = list((await rls_sess1.execute(_USER_ID_QUERY)).scalars())
                result2 = list((await rls_sess2.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(result1, [1])
                self.assertEqual(result2, [2])

                # Bypass session1 only
                async with rls_sess1.bypass_rls():
                    result1_bypass = list(
                        (await rls_sess1.execute(_USER_ID_QUERY)).scalars()
                    )
                    result2_no_bypass = list(
                        (await rls_sess2.execute(_USER_ID_QUERY)).scalars()
                    )
                    self.assertEqual(
                        result1_bypass, [1, 2], "Bypassed session should see all users."
                    )
                    self.assertEqual(
                        result2_no_bypass,
                        [2],
                        "Non-bypassed session should see only its account's user.",
                    )

                # After bypass exits, session1 is restricted again
                result1_after = list(
                    (await rls_sess1.execute(_USER_ID_QUERY)).scalars()
                )
                self.assertEqual(result1_after, [1])
        await rls_sess1.close()
        await rls_sess2.close()


class TestAsyncSQLInjectionProtection(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()

    @classmethod
    def tearDownClass(cls):
        cls.instance.close()

    async def test_malicious_context_value_does_not_execute_sql_injection(self):
        """A malicious string value in the async context is treated as a literal
        string and does not allow SQL injection through the RLS session variables."""

        class StringContext(pydantic.BaseModel):
            account_id: str

        context = StringContext(account_id=_MALICIOUS_CONTEXT_VALUE)
        rls_sess = rls_session.AsyncRlsSession(
            context=context, bind=self.instance.async_non_superadmin_engine
        )

        async with rls_sess.begin():
            await rls_sess.execute(sqlalchemy.text("SELECT 1"))

            # Verify the malicious payload was stored as a literal string, not executed
            result = await rls_sess.execute(
                sqlalchemy.text("SELECT current_setting('rls.account_id', true);")
            )
            stored_value = result.scalar()
            self.assertEqual(
                stored_value,
                _MALICIOUS_CONTEXT_VALUE,
                "Context value must be stored as a literal string, not interpreted as SQL.",
            )

        # Verify the schema and its tables still exist (DROP SCHEMA was not executed)
        async with self.instance.async_non_superadmin_engine.connect() as conn:
            result = await conn.execute(
                sqlalchemy.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public';"
                )
            )
            tables = result.fetchall()
            self.assertGreater(
                len(tables),
                0,
                "Public schema tables must still exist after a context with a malicious value.",
            )


if __name__ == "__main__":
    unittest.main()
