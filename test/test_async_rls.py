import asyncio
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
_NOOP_QUERY = sqlalchemy.text("SELECT 1;")


async def rls_setting(
    session: rls_session.AsyncRlsSession, setting_name: str
) -> str | None:
    """Reads a PostgreSQL RLS session setting value."""
    result = await sa_asyncio.AsyncSession.execute(
        session, sqlalchemy.text(f"SELECT current_setting('rls.{setting_name}', true);")
    )
    return result.scalar()


async def rls_bypassed(session: rls_session.AsyncRlsSession) -> bool:
    """Returns True if RLS is currently bypassed in the session."""
    str_value = await rls_setting(session, "bypass_rls")
    if str_value == "true":
        return True
    if str_value == "false":
        return False
    raise ValueError(f"Unexpected value for bypass_rls setting: '{str_value}'")


class AsyncRLSTests(unittest.IsolatedAsyncioTestCase):
    instance: database.TestPostgres
    engine: sa_asyncio.AsyncEngine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.engine = sa_asyncio.create_async_engine(cls.instance.url)

    @classmethod
    def tearDownClass(cls):
        asyncio.run(cls.engine.dispose())
        cls.instance.close()

    def _new_session(self, account_id: int = 1) -> rls_session.AsyncRlsSession:
        return rls_session.AsyncRlsSession(
            context=models.SampleRlsContext(account_id=account_id),
            bind=self.engine,
        )

    async def test_rls_query_with_async_rls_session(self):
        """AsyncRlsSession applies RLS and returns only the matching user."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    async def test_rls_query_with_async_rls_session_and_bypass(self):
        """AsyncRlsSession with bypass_rls returns all users."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(result, [1, 2])
        await rls_sess.close()

    async def test_bypass_rls_setting_single(self):
        """bypass_rls pg setting toggles when entering and exiting bypass context."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            self.assertFalse(await rls_bypassed(rls_sess))
            await rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(await rls_bypassed(rls_sess))
            async with rls_sess.bypass_rls():
                await rls_sess.execute(_NOOP_QUERY)
                self.assertTrue(await rls_bypassed(rls_sess))
            await rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(await rls_bypassed(rls_sess))
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
        self.assertEqual(rls_sess._rls_bypass_depth, 0)
        # A new transaction should see no bypass
        async with rls_sess.begin():
            self.assertFalse(await rls_bypassed(rls_sess))
        await rls_sess.close()

    async def test_nested_bypass_rls(self):
        """Nested bypass_rls contexts maintain bypass until all contexts exit."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                await rls_sess.execute(_NOOP_QUERY)
                self.assertTrue(await rls_bypassed(rls_sess))
                async with rls_sess.bypass_rls():
                    await rls_sess.execute(_NOOP_QUERY)
                    self.assertTrue(await rls_bypassed(rls_sess))
                await rls_sess.execute(_NOOP_QUERY)
                self.assertTrue(await rls_bypassed(rls_sess))
            await rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(await rls_bypassed(rls_sess))
        await rls_sess.close()

    async def test_python_exception_during_bypass_restores_state(self):
        """After a Python exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with self.assertRaises(ValueError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    raise ValueError("Test")
        self.assertEqual(rls_sess._rls_bypass_depth, 0)
        async with rls_sess.begin():
            self.assertFalse(await rls_bypassed(rls_sess))
        await rls_sess.close()

    async def test_none_context_field_clears_rls_setting(self):
        """A nullable pydantic field set to None resets the corresponding RLS pg setting."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            setting = await rls_setting(rls_sess, "account_id")
            self.assertEqual(
                setting,
                "",
                "RLS setting for a None context field must be reset to empty string.",
            )
        await rls_sess.close()

    async def test_none_context_field_filters_results(self):
        """A nullable pydantic field set to None returns no rows."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(rows, [], "Expected no rows when account_id is None.")
        await rls_sess.close()

    async def test_none_context_returns_no_rows(self):
        """Passing context=None to AsyncRlsSession returns no rows."""
        rls_sess = rls_session.AsyncRlsSession(context=None, bind=self.engine)
        async with rls_sess.begin():
            rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(rows, [], "Expected no rows when context is None.")
        await rls_sess.close()

    async def test_mutable_context_change_reapplies_rls_setting(self):
        """Changing a mutable context field triggers RLS setting re-application."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            first_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(first_rows, [1])
            context.account_id = 2
            second_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(second_rows, [2])
        await rls_sess.close()

    async def test_immutable_context_only_sets_rls_setting_once_per_transaction(self):
        """An immutable context avoids redundant RLS setting re-application."""
        context = models.ImmutableEqGuardRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)

        async with rls_sess.begin():
            first_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            second_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(first_rows, [1])
            self.assertEqual(second_rows, [1])
        await rls_sess.close()

    async def test_immutable_context_skips_equality_check_when_clean(self):
        """Immutable contexts skip equality checks after initial application."""
        context = models.ImmutableEqGuardRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            first_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            second_rows = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(first_rows, [1])
            self.assertEqual(second_rows, [1])
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
                    # Now both are bypassed
                    async with rls_sess2.bypass_rls():
                        result1_bypass = list(
                            (await rls_sess1.execute(_USER_ID_QUERY)).scalars()
                        )
                        result2_bypass = list(
                            (await rls_sess2.execute(_USER_ID_QUERY)).scalars()
                        )
                        self.assertEqual(result1_bypass, [1, 2])
                        self.assertEqual(result2_bypass, [1, 2])

                # After bypass exits, session1 is restricted again
                result1_after = list(
                    (await rls_sess1.execute(_USER_ID_QUERY)).scalars()
                )
                self.assertEqual(result1_after, [1])
        await rls_sess1.close()
        await rls_sess2.close()

    async def test_rls_context_variable_persists_after_commit(self):
        """RLS context variables (e.g. account_id) still filter correctly after commit."""
        rls_sess = self._new_session(account_id=1)
        # Use autobegin (no explicit begin()) so we can manually commit
        result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
        self.assertEqual(result, [1])
        await rls_sess.commit()
        # After commit a new autobegin transaction starts; context must still filter
        result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
        self.assertEqual(
            result,
            [1],
            "RLS context variable must still filter rows after commit.",
        )
        await rls_sess.close()

    async def test_bypass_rls_persists_across_commit(self):
        """bypass_rls state persists across commit within the bypass context."""
        rls_sess = self._new_session()
        async with rls_sess.bypass_rls():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1, 2])
            self.assertTrue(await rls_bypassed(rls_sess))
            await rls_sess.commit()
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1, 2])
            self.assertTrue(await rls_bypassed(rls_sess))
        result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
        self.assertEqual(result, [1])
        self.assertFalse(await rls_bypassed(rls_sess))
        await rls_sess.close()

    async def test_begin_sets_rls_account_id_setting(self):
        """begin() sets the rls.account_id pg setting to the context value."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
        await rls_sess.close()

    async def test_scalar_sets_rls_settings(self):
        """scalar() applies RLS and returns only the account's user id."""
        rls_sess = self._new_session(account_id=1)
        result = await rls_sess.scalar(_USER_ID_QUERY)
        self.assertEqual(result, 1)
        await rls_sess.close()

    async def test_scalars_sets_rls_settings(self):
        """scalars() applies RLS and returns only the account's user id."""
        rls_sess = self._new_session(account_id=1)
        result = list(await rls_sess.scalars(_USER_ID_QUERY))
        self.assertEqual(result, [1])
        await rls_sess.close()

    async def test_flush_preserves_rls_settings(self):
        """flush() does not disrupt the rls.account_id setting established by begin()."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            await rls_sess.flush()
            self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    async def test_begin_sets_rls_with_user_orm(self):
        """begin() sets rls.account_id and ORM User query returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
            users = list(
                await rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users], [1])
        await rls_sess.close()

    async def test_scalar_with_user_orm_applies_rls(self):
        """scalar() with User ORM model returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        user = await rls_sess.scalar(
            sqlalchemy.select(models.User).order_by(models.User.id)
        )
        self.assertIsNotNone(user)
        self.assertEqual(user.id, 1)
        await rls_sess.close()

    async def test_scalar_with_user_orm_hides_other_account(self):
        """scalar() with User ORM model does not return a user from another account."""
        rls_sess = self._new_session(account_id=1)
        user = await rls_sess.scalar(
            sqlalchemy.select(models.User).where(models.User.id == 2)
        )
        self.assertIsNone(user)
        await rls_sess.close()

    async def test_scalars_with_user_orm_applies_rls(self):
        """scalars() with User ORM model returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        users = list(
            await rls_sess.scalars(
                sqlalchemy.select(models.User).order_by(models.User.id)
            )
        )
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].id, 1)
        await rls_sess.close()

    async def test_scalars_with_user_orm_different_account(self):
        """scalars() with User ORM model returns only the correct account's user."""
        rls_sess = self._new_session(account_id=2)
        users = list(
            await rls_sess.scalars(
                sqlalchemy.select(models.User).order_by(models.User.id)
            )
        )
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].id, 2)
        await rls_sess.close()

    async def test_flush_with_user_orm_preserves_rls(self):
        """flush() after loading User ORM objects preserves RLS filtering."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            users = list(
                await rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users], [1])
            await rls_sess.flush()
            self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
            users_after_flush = list(
                await rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users_after_flush], [1])
        await rls_sess.close()

    async def test_malicious_context_value_does_not_execute_sql_injection(self) -> None:
        """A malicious string value in the async context is treated as a literal
        string and does not allow SQL injection through the RLS session variables."""

        class StringContext(pydantic.BaseModel):
            account_id: str

        context = StringContext(account_id=_MALICIOUS_CONTEXT_VALUE)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)

        async with rls_sess.begin():
            await rls_sess.execute(_NOOP_QUERY)
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
        await rls_sess.close()

        # Verify the schema and its tables still exist (DROP SCHEMA was not executed)
        async with self.engine.connect() as conn:
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


class AsyncRlsSessionTransactionTests(unittest.IsolatedAsyncioTestCase):
    """Tests for the :class:`RlsAsyncSessionTransaction` wrapper."""

    instance: database.TestPostgres
    engine: sa_asyncio.AsyncEngine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.engine = sa_asyncio.create_async_engine(cls.instance.url)

    @classmethod
    def tearDownClass(cls):
        asyncio.run(cls.engine.dispose())
        cls.instance.close()

    def _new_session(self, account_id: int = 1) -> rls_session.AsyncRlsSession:
        return rls_session.AsyncRlsSession(
            context=models.SampleRlsContext(account_id=account_id),
            bind=self.engine,
        )

    # -- type / identity ----------------------------------------------------

    async def test_begin_returns_rls_async_session_transaction(self):
        """begin() returns an RlsAsyncSessionTransaction, not a raw AsyncSessionTransaction."""
        rls_sess = self._new_session()
        async with rls_sess.begin() as tx:
            self.assertIsInstance(tx, rls_session.RlsAsyncSessionTransaction)
            self.assertNotIsInstance(tx, sa_asyncio.AsyncSessionTransaction)
        await rls_sess.close()

    async def test_transaction_session_property(self):
        """The transaction's .session property points back at the owning AsyncRlsSession."""
        rls_sess = self._new_session()
        async with rls_sess.begin() as tx:
            self.assertIs(tx.session, rls_sess)
        await rls_sess.close()

    # -- proxy properties ---------------------------------------------------

    async def test_transaction_is_active_inside_block(self):
        """is_active is True while the async transaction is open."""
        rls_sess = self._new_session()
        async with rls_sess.begin() as tx:
            self.assertTrue(tx.is_active)
        await rls_sess.close()

    async def test_transaction_nested_is_false(self):
        """A regular begin() transaction is not nested."""
        rls_sess = self._new_session()
        async with rls_sess.begin() as tx:
            self.assertFalse(tx.nested)
        await rls_sess.close()

    async def test_transaction_sync_transaction_property(self):
        """sync_transaction proxies the underlying SessionTransaction."""
        rls_sess = self._new_session()
        async with rls_sess.begin() as tx:
            self.assertIsNotNone(tx.sync_transaction)
        await rls_sess.close()

    # -- RLS filtering via transaction --------------------------------------

    async def test_rls_filtering_through_transaction(self):
        """Queries executed within the async transaction block apply RLS."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    async def test_begin_sets_rls_setting_via_transaction(self):
        """begin() sets the rls.account_id pg setting via the async transaction wrapper."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
        await rls_sess.close()

    # -- commit / rollback dirty tracking -----------------------------------

    async def test_explicit_commit_sets_dirty(self):
        """Calling tx.commit() marks the session as dirty."""
        rls_sess = self._new_session()
        tx = rls_sess.begin()
        await tx.__aenter__()
        rls_sess._rls_dirty = False
        await tx.commit()
        self.assertTrue(rls_sess._rls_dirty)
        # Transaction is now committed; clean up without committing again
        await tx.__aexit__(None, None, None)
        await rls_sess.close()

    async def test_explicit_rollback_sets_dirty(self):
        """Calling tx.rollback() marks the session as dirty."""
        rls_sess = self._new_session()
        tx = rls_sess.begin()
        await tx.__aenter__()
        rls_sess._rls_dirty = False
        await tx.rollback()
        self.assertTrue(rls_sess._rls_dirty)
        await tx.__aexit__(None, None, None)
        await rls_sess.close()

    async def test_context_exit_commit_sets_dirty(self):
        """Normal context-manager exit (implicit commit) marks the session as dirty."""
        rls_sess = self._new_session()
        async with rls_sess.begin():
            rls_sess._rls_dirty = False
        self.assertTrue(rls_sess._rls_dirty)
        await rls_sess.close()

    async def test_context_exit_rollback_on_exception_sets_dirty(self):
        """Context-manager exit with an exception (implicit rollback) marks dirty."""
        rls_sess = self._new_session()
        with self.assertRaises(ValueError):
            async with rls_sess.begin():
                rls_sess._rls_dirty = False
                raise ValueError("boom")
        self.assertTrue(rls_sess._rls_dirty)
        await rls_sess.close()

    # -- RLS re-application after commit ------------------------------------

    async def test_rls_reapplied_after_transaction_commit(self):
        """After a transaction, a new begin() still applies RLS."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    async def test_rls_reapplied_after_transaction_rollback_on_error(self):
        """After an exception rolls back the transaction, a new begin() still applies RLS."""
        rls_sess = self._new_session(account_id=1)
        with self.assertRaises(ValueError):
            async with rls_sess.begin():
                raise ValueError("test")
        async with rls_sess.begin():
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    # -- bypass within transaction ------------------------------------------

    async def test_bypass_rls_within_transaction(self):
        """bypass_rls inside an async transaction block still works correctly."""
        rls_sess = self._new_session(account_id=1)
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(result, [1, 2])
            result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(result, [1])
        await rls_sess.close()

    # -- different accounts via transaction ---------------------------------

    async def test_different_accounts_via_transaction(self):
        """Two async sessions with different contexts see different data."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        async with rls_sess1.begin():
            async with rls_sess2.begin():
                r1 = list((await rls_sess1.execute(_USER_ID_QUERY)).scalars())
                r2 = list((await rls_sess2.execute(_USER_ID_QUERY)).scalars())
                self.assertEqual(r1, [1])
                self.assertEqual(r2, [2])
        await rls_sess1.close()
        await rls_sess2.close()

    # -- await protocol -----------------------------------------------------

    async def test_await_begin_returns_transaction(self):
        """Awaiting begin() returns an RlsAsyncSessionTransaction."""
        rls_sess = self._new_session()
        tx = await rls_sess.begin()
        self.assertIsInstance(tx, rls_session.RlsAsyncSessionTransaction)
        await tx.rollback()
        await rls_sess.close()

    async def test_await_begin_applies_rls(self):
        """Awaiting begin() also applies RLS settings."""
        rls_sess = self._new_session(account_id=1)
        tx = await rls_sess.begin()
        self.assertEqual(await rls_setting(rls_sess, "account_id"), "1")
        result = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
        self.assertEqual(result, [1])
        await tx.rollback()
        await rls_sess.close()

    async def test_mutable_context_reapplied_via_transaction(self):
        """Changing a mutable context mid-transaction re-applies RLS."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=self.engine)
        async with rls_sess.begin():
            first = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(first, [1])
            context.account_id = 2
            second = list((await rls_sess.execute(_USER_ID_QUERY)).scalars())
            self.assertEqual(second, [2])
        await rls_sess.close()


if __name__ == "__main__":
    unittest.main()
