import enum
import typing
import unittest

import pydantic
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy import orm

from rls import create_policies
from rls import policy
from rls import register
from rls import rls_sessioner
from rls import session
from test import database
from test import models

_MALICIOUS_CONTEXT_VALUE = "foo; DROP SCHEMA IF EXISTS PUBLIC CASCADE;"
_USER_ID_QUERY = sqlalchemy.text("SELECT id FROM users ORDER BY id ASC")
_NOOP_QUERY = sqlalchemy.text("SELECT 1;")
_ERROR_QUERY = sqlalchemy.text("SELECT 1/0;")


def rls_setting(session: session.RlsSession, setting_name: str) -> str | None:
    """Reads a PostgreSQL RLS session setting value."""
    return orm.Session.execute(
        session, sqlalchemy.text(f"SELECT current_setting('rls.{setting_name}', true);")
    ).scalar()


def rls_bypassed(session: session.RlsSession) -> bool:
    """Returns True if RLS is currently bypassed in the session."""
    str_value = rls_setting(session, "bypass_rls")
    if str_value == "true":
        return True
    if str_value == "false":
        return False
    raise ValueError(f"Unexpected value for bypass_rls setting: '{str_value}'")


class SyncRLSTests(unittest.TestCase):
    instance: database.TestPostgres
    engine: sqlalchemy.engine.Engine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        cls.engine = sqlalchemy.create_engine(cls.instance.url)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.instance.close()

    def _new_session(self, account_id: int = 1) -> session.RlsSession:
        return session.RlsSession(
            context=models.SampleRlsContext(account_id=account_id),
            bind=self.engine,
        )

    def test_rls_query_with_rls_session_and_bypass(self):
        context = models.SampleRlsContext(account_id=1)

        rls_sess = session.RlsSession(context=context, bind=self.engine)

        with rls_sess.begin():
            # Test Policy on table users with SELECT where (id = account_id)
            my_user = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(my_user, [1])

            # Test bypassing RLS
            with rls_sess.bypass_rls():
                my_user = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(my_user, [1, 2])

    def test_rls_query_with_rls_sessioner_and_bypass(self):
        # Concrete implementation of ContextGetter
        class ExampleContextGetter(rls_sessioner.ContextGetter):
            def get_context(self, *args, **kwargs) -> models.SampleRlsContext:
                account_id = kwargs.get("account_id", 1)
                return models.SampleRlsContext(account_id=account_id)

        session_maker = orm.sessionmaker(
            class_=session.RlsSession,
            autoflush=False,
            autocommit=False,
            bind=self.engine,
        )
        my_sessioner = rls_sessioner.RlsSessioner(
            sessionmaker=session_maker, context_getter=ExampleContextGetter()
        )

        with my_sessioner(account_id=1) as rls_sess:
            res = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(res, [1])

            with rls_sess.bypass_rls():
                res = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(res, [1, 2])

    def test_bypass_rls_setting_single(self):
        """bypass_rls pg setting toggles when entering and exiting bypass context."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            self.assertFalse(rls_bypassed(rls_sess))
            rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(rls_bypassed(rls_sess))
            with rls_sess.bypass_rls():
                rls_sess.execute(_NOOP_QUERY)
                self.assertTrue(rls_bypassed(rls_sess))
            rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(rls_bypassed(rls_sess))
        rls_sess.close()

    def test_exception_during_bypass_propagates(self):
        """Exceptions raised inside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with (
            self.assertRaises(sqlalchemy.exc.DataError),
            rls_sess.begin(),
            rls_sess.bypass_rls(),
        ):
            rls_sess.execute(_ERROR_QUERY)
        rls_sess.close()

    def test_exception_without_bypass_propagates(self):
        """Exceptions raised outside bypass_rls propagate to the caller."""
        rls_sess = self._new_session()
        with self.assertRaises(sqlalchemy.exc.DataError), rls_sess.begin():
            rls_sess.execute(_ERROR_QUERY)
        rls_sess.close()

    def test_sql_exception_during_bypass_restores_state(self):
        """After a SQL exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with (
            self.assertRaises(sqlalchemy.exc.DataError),
            rls_sess.begin(),
            rls_sess.bypass_rls(),
        ):
            rls_sess.execute(_ERROR_QUERY)
        # _rls_bypass flag must be cleared regardless of exception
        self.assertEqual(rls_sess._rls_bypass_depth, 0)
        # A new transaction should see no bypass
        with rls_sess.begin():
            self.assertFalse(rls_bypassed(rls_sess))
        rls_sess.close()

    def test_nested_bypass_rls(self):
        """Nested bypass_rls contexts maintain bypass until all contexts exit."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            with rls_sess.bypass_rls():
                rls_sess.execute(_NOOP_QUERY)
                self.assertTrue(rls_bypassed(rls_sess))
                with rls_sess.bypass_rls():
                    self.assertTrue(rls_bypassed(rls_sess))
                self.assertTrue(rls_bypassed(rls_sess))
            rls_sess.execute(_NOOP_QUERY)
            self.assertFalse(rls_bypassed(rls_sess))
        rls_sess.close()

    def test_python_exception_during_bypass_restores_state(self):
        """After a Python exception inside bypass_rls, bypass state is cleared."""
        rls_sess = self._new_session()
        with (
            self.assertRaises(ValueError),
            rls_sess.begin(),
            rls_sess.bypass_rls(),
        ):
            raise ValueError("Test")
        self.assertEqual(rls_sess._rls_bypass_depth, 0)
        with rls_sess.begin():
            self.assertFalse(rls_bypassed(rls_sess))
        rls_sess.close()

    def test_sql_error_caught_inside_bypass_context_restores_rls(self):
        """SQL error caught inside bypass_rls via savepoint keeps bypass active;
        RLS is correctly re-applied after the bypass context exits normally."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            with rls_sess.bypass_rls():
                # Execute a no-op first so the bypass setting is flushed to
                # PostgreSQL before the savepoint is created.  After the
                # savepoint rolls back it will correctly restore bypass_rls=true.
                rls_sess.execute(_NOOP_QUERY)
                # Catch the SQL error inside the bypass context using a savepoint
                # so the outer transaction remains usable.
                with (
                    self.assertRaises(sqlalchemy.exc.DataError),
                    rls_sess.begin_nested(),
                ):
                    rls_sess.execute(_ERROR_QUERY)
                # Still inside bypass_rls: bypass must still be active and all
                # rows should be visible.
                self.assertTrue(rls_bypassed(rls_sess))
                all_ids = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(all_ids, [1, 2])
            # After the bypass context exits normally, RLS must be re-applied
            # and only the rows belonging to account_id=1 should be visible.
            restricted_ids = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(restricted_ids, [1])
        rls_sess.close()

    def test_sql_error_caught_outside_bypass_context_restores_rls(self):
        """SQL error propagating out of bypass_rls is caught externally;
        bypass depth resets to 0 and RLS data filtering works in the next
        transaction."""
        rls_sess = self._new_session(account_id=1)
        with (
            self.assertRaises(sqlalchemy.exc.DataError),
            rls_sess.begin(),
            rls_sess.bypass_rls(),
        ):
            # Error propagates out of both the bypass and begin contexts.
            rls_sess.execute(_ERROR_QUERY)
        # Bypass depth must be reset regardless of the exception path.
        self.assertEqual(rls_sess._rls_bypass_depth, 0)
        # In the next transaction RLS must filter rows to only account_id=1.
        with rls_sess.begin():
            restricted_ids = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(restricted_ids, [1])
        rls_sess.close()

    def test_multiple_sessions_bypass_isolated(self):
        """Bypassing RLS on one session does not affect a concurrent session."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        with rls_sess1.begin(), rls_sess2.begin():
            # Without bypass each session sees only its own user
            result1 = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
            result2 = list(rls_sess2.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result1, [1])
            self.assertEqual(result2, [2])

            # Bypass session1 only
            with rls_sess1.bypass_rls():
                result1_bypass = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
                result2_no_bypass = list(rls_sess2.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(
                    result1_bypass, [1, 2], "Bypassed session should see all users."
                )
                self.assertEqual(
                    result2_no_bypass,
                    [2],
                    "Non-bypassed session should see only its account's user.",
                )
                # Now both are bypassed
                with rls_sess2.bypass_rls():
                    result1_bypass = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
                    result2_bypass = list(rls_sess2.execute(_USER_ID_QUERY).scalars())
                    self.assertEqual(result1_bypass, [1, 2])
                    self.assertEqual(result2_bypass, [1, 2])

            # After bypass exits, session1 is restricted again
            result1_after = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result1_after, [1])
        rls_sess1.close()
        rls_sess2.close()

    def test_none_context_field_clears_rls_setting(self):
        """A nullable pydantic field set to None filters all rows."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(rows, [], "Expected no rows when account_id is None.")
        rls_sess.close()

    def test_none_context_field_filters_results(self):
        """A nullable pydantic field set to None returns no rows."""
        context = models.SampleRlsContext(account_id=None)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(rows, [], "Expected no rows when account_id is None.")
        rls_sess.close()

    def test_int_enum_context_field_filters_results(self):
        """An enum context field is sent by value, so the policy cast works."""

        class Account(enum.IntEnum):
            first = 1

        class EnumContext(pydantic.BaseModel):
            account_id: Account

        rls_sess = session.RlsSession(
            context=EnumContext(account_id=Account.first), bind=self.engine
        )
        with rls_sess.begin():
            self.assertEqual(rls_setting(rls_sess, "account_id"), "1")
            rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(rows, [1])
        rls_sess.close()

    def test_optional_annotated_context_field_filters_results(self):
        """An Optional field wrapping a constrained type (e.g. PositiveInt) is
        accepted; a value filters rows and None matches none."""

        class OptionalContext(pydantic.BaseModel):
            account_id: pydantic.PositiveInt | None = None

        for account_id, expected_setting, expected_rows in [
            (2, "2", [2]),
            (None, "", []),
        ]:
            with (
                self.subTest(account_id=account_id),
                session.RlsSession(
                    context=OptionalContext(account_id=account_id), bind=self.engine
                ) as rls_sess,
                rls_sess.begin(),
            ):
                self.assertEqual(rls_setting(rls_sess, "account_id"), expected_setting)
                rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(rows, expected_rows)

    def test_none_context_returns_no_rows(self):
        """Passing context=None to RlsSession returns no rows."""
        rls_sess = session.RlsSession(context=None, bind=self.engine)
        with rls_sess.begin():
            rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(rows, [], "Expected no rows when context is None.")
        rls_sess.close()

    def test_mutable_context_change_reapplies_rls_setting(self):
        """Changing a mutable context field triggers RLS setting re-application."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            first_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(first_rows, [1])
            context.account_id = 2
            second_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(second_rows, [2])
        rls_sess.close()

    def test_immutable_context_only_sets_rls_setting_once_per_transaction(self):
        """An immutable context avoids redundant RLS setting re-application."""
        context = models.ImmutableEqGuardRlsContext(account_id=1)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            first_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            second_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(first_rows, [1])
            self.assertEqual(second_rows, [1])
        rls_sess.close()

    def test_immutable_context_skips_equality_check_when_clean(self):
        """Immutable contexts skip equality checks after initial application."""
        context = models.ImmutableEqGuardRlsContext(account_id=1)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            first_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            second_rows = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(first_rows, [1])
            self.assertEqual(second_rows, [1])
        rls_sess.close()

    def test_different_contexts_see_different_data(self):
        """Sessions created with different account_ids each see only their own user."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        with rls_sess1.begin(), rls_sess2.begin():
            result1 = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
            result2 = list(rls_sess2.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result1, [1])
            self.assertEqual(result2, [2])
        rls_sess1.close()
        rls_sess2.close()

    def test_rollback_bypass_interaction(self):
        rls_sess = self._new_session(account_id=1)
        result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
        self.assertEqual(result, [1])
        rls_sess.rollback()
        result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
        self.assertEqual(result, [1])
        with rls_sess.bypass_rls():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1, 2])
            rls_sess.rollback()
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1, 2])
            rls_sess.rollback()
            with rls_sess.bypass_rls():
                result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(result, [1, 2])
        rls_sess.close()

    def test_rls_context_variable_persists_after_commit(self):
        """RLS context variables (e.g. account_id) still filter correctly after commit."""
        rls_sess = self._new_session(account_id=1)
        # Use autobegin (no explicit begin()) so we can manually commit
        result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
        self.assertEqual(result, [1])
        rls_sess.commit()
        # After commit a new autobegin transaction starts; context must still filter
        result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
        self.assertEqual(
            result,
            [1],
            "RLS context variable must still filter rows after commit.",
        )
        rls_sess.close()

    def test_bypass_rls_persists_across_commit(self):
        """bypass_rls state persists across commit within the bypass context."""
        rls_sess = self._new_session()
        with rls_sess.bypass_rls():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1, 2])
            self.assertTrue(rls_bypassed(rls_sess))
            rls_sess.commit()
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1, 2])
            self.assertTrue(rls_bypassed(rls_sess))
        result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
        self.assertEqual(result, [1])
        self.assertFalse(rls_bypassed(rls_sess))
        rls_sess.close()

    def test_scalar_sets_rls_settings(self):
        """scalar() applies RLS and returns only the account's user id."""
        rls_sess = self._new_session(account_id=1)
        result = rls_sess.scalar(_USER_ID_QUERY)
        self.assertEqual(result, 1)
        rls_sess.close()

    def test_scalars_sets_rls_settings(self):
        """scalars() applies RLS and returns only the account's user id."""
        rls_sess = self._new_session(account_id=1)
        result = list(rls_sess.scalars(_USER_ID_QUERY))
        self.assertEqual(result, [1])
        rls_sess.close()

    def test_flush_preserves_rls_settings(self):
        """flush() does not disrupt the rls.account_id setting established by begin()."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            rls_sess.flush()
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        rls_sess.close()

    def test_begin_sets_rls_with_user_orm(self):
        """begin() sets rls.account_id and ORM User query returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            users = list(
                rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users], [1])
        rls_sess.close()

    def test_scalar_with_user_orm_applies_rls(self):
        """scalar() with User ORM model returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        user = rls_sess.scalar(sqlalchemy.select(models.User).order_by(models.User.id))
        self.assertIsNotNone(user)
        self.assertEqual(user.id, 1)
        rls_sess.close()

    def test_scalar_with_user_orm_hides_other_account(self):
        """scalar() with User ORM model does not return a user from another account."""
        rls_sess = self._new_session(account_id=1)
        user = rls_sess.scalar(
            sqlalchemy.select(models.User).where(models.User.id == 2)
        )
        self.assertIsNone(user)
        rls_sess.close()

    def test_scalars_with_user_orm_applies_rls(self):
        """scalars() with User ORM model returns only the account's user."""
        rls_sess = self._new_session(account_id=1)
        users = list(
            rls_sess.scalars(sqlalchemy.select(models.User).order_by(models.User.id))
        )
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].id, 1)
        rls_sess.close()

    def test_scalars_with_user_orm_different_account(self):
        """scalars() with User ORM model returns only the correct account's user."""
        rls_sess = self._new_session(account_id=2)
        users = list(
            rls_sess.scalars(sqlalchemy.select(models.User).order_by(models.User.id))
        )
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].id, 2)
        rls_sess.close()

    def test_flush_with_user_orm_preserves_rls(self):
        """flush() after loading User ORM objects preserves RLS filtering."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            users = list(
                rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users], [1])
            rls_sess.flush()
            users_after_flush = list(
                rls_sess.scalars(
                    sqlalchemy.select(models.User).order_by(models.User.id)
                )
            )
            self.assertEqual([u.id for u in users_after_flush], [1])
        rls_sess.close()

    def test_malicious_context_value_does_not_execute_sql_injection(self) -> None:
        """A malicious string value in the context is treated as a literal string
        and does not allow SQL injection through the RLS session variables."""

        class StringContext(pydantic.BaseModel):
            account_id: str

        context = StringContext(account_id=_MALICIOUS_CONTEXT_VALUE)
        rls_sess = session.RlsSession(context=context, bind=self.engine)

        with rls_sess.begin():
            rls_sess.execute(_NOOP_QUERY)

            # Verify the malicious payload was stored as a literal string, not executed
            stored_value = rls_sess.execute(
                sqlalchemy.text("SELECT current_setting('rls.account_id', true);")
            ).scalar()
            self.assertEqual(
                stored_value,
                _MALICIOUS_CONTEXT_VALUE,
                "Context value must be stored as a literal string, not interpreted as SQL.",
            )

        # Verify the schema and its tables still exist (DROP SCHEMA was not executed)
        with self.engine.connect() as conn:
            tables = conn.execute(
                sqlalchemy.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public';"
                )
            ).fetchall()
            self.assertGreater(
                len(tables),
                0,
                "Public schema tables must still exist after a context with a malicious value.",
            )

    def test_begin_returns_rls_session_transaction(self):
        """begin() returns an RlsSessionTransaction, not the session itself."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            self.assertIsInstance(tx, session.RlsSessionTransaction)
            self.assertNotIsInstance(tx, session.RlsSession)
        rls_sess.close()

    def test_transaction_session_property(self):
        """The transaction's .session property points back at the owning RlsSession."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            self.assertIs(tx.session, rls_sess)
        rls_sess.close()

    def test_transaction_is_active_inside_block(self):
        """is_active is True while the transaction is open."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            self.assertTrue(tx.is_active)
        rls_sess.close()

    def test_transaction_nested_is_false(self):
        """A regular begin() transaction is not nested (no SAVEPOINT)."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            self.assertFalse(tx.nested)
        rls_sess.close()

    def test_transaction_parent_is_none(self):
        """A top-level begin() transaction has no parent."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            self.assertIsNone(tx.parent)
        rls_sess.close()

    def test_rls_filtering_through_transaction(self):
        """Queries executed via the session within a transaction block apply RLS."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        rls_sess.close()

    def test_transaction_explicit_commit_sets_dirty(self):
        """Calling tx.commit() inside the block marks the session as dirty."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            rls_sess._rls_dirty = False
            tx.commit()
            self.assertTrue(rls_sess._rls_dirty)
        rls_sess.close()

    def test_transaction_explicit_rollback_sets_dirty(self):
        """Calling tx.rollback() inside the block marks the session as dirty."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            rls_sess._rls_dirty = False
            tx.rollback()
            self.assertTrue(rls_sess._rls_dirty)
        rls_sess.close()

    def test_transaction_context_exit_commit_sets_dirty(self):
        """Normal context-manager exit (implicit commit) marks the session as dirty."""
        rls_sess = self._new_session()
        with rls_sess.begin():
            rls_sess._rls_dirty = False
        self.assertTrue(rls_sess._rls_dirty)
        rls_sess.close()

    def test_transaction_context_exit_rollback_on_exception_sets_dirty(self):
        """Context-manager exit with an exception (implicit rollback) marks dirty."""
        rls_sess = self._new_session()
        with self.assertRaises(ValueError), rls_sess.begin():
            rls_sess._rls_dirty = False
            raise ValueError("boom")
        self.assertTrue(rls_sess._rls_dirty)
        rls_sess.close()

    def test_rls_reapplied_after_transaction_commit(self):
        """After an explicit tx.commit(), a new begin() still applies RLS."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        with rls_sess.begin():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        rls_sess.close()

    def test_rls_reapplied_after_transaction_rollback_on_error(self):
        """After an exception rolls back the transaction, a new begin() still applies RLS."""
        rls_sess = self._new_session(account_id=1)
        with self.assertRaises(ValueError), rls_sess.begin():
            raise ValueError("test")
        with rls_sess.begin():
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        rls_sess.close()

    def test_bypass_rls_within_transaction(self):
        """bypass_rls inside a transaction block still works correctly."""
        rls_sess = self._new_session(account_id=1)
        with rls_sess.begin():
            with rls_sess.bypass_rls():
                result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
                self.assertEqual(result, [1, 2])
            result = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(result, [1])
        rls_sess.close()

    def test_different_accounts_via_transaction(self):
        """Two sessions with different contexts see different data."""
        rls_sess1 = self._new_session(account_id=1)
        rls_sess2 = self._new_session(account_id=2)
        with rls_sess1.begin(), rls_sess2.begin():
            r1 = list(rls_sess1.execute(_USER_ID_QUERY).scalars())
            r2 = list(rls_sess2.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(r1, [1])
            self.assertEqual(r2, [2])
        rls_sess1.close()
        rls_sess2.close()

    def test_transaction_close_delegates(self):
        """tx.close() delegates to the underlying SessionTransaction."""
        rls_sess = self._new_session()
        with rls_sess.begin() as tx:
            tx.close()
        rls_sess.close()

    def test_transaction_mutable_context_reapplied(self):
        """Changing a mutable context mid-transaction re-applies RLS."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = session.RlsSession(context=context, bind=self.engine)
        with rls_sess.begin():
            first = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(first, [1])
            context.account_id = 2
            second = list(rls_sess.execute(_USER_ID_QUERY).scalars())
            self.assertEqual(second, [2])
        rls_sess.close()

    def test_two_phase_commit_with_update(self):
        """Two-phase commit (prepare + commit) with an UPDATE restricted by RLS.

        The UPDATE targets all rows; RLS (account_id=1) silently restricts the
        write to the single matching row.  The follow-up SELECT also uses no
        WHERE clause — RLS is solely responsible for returning only that row.
        """
        # No WHERE clause: without RLS this would update both users.
        # Use id-based value to avoid a unique-constraint violation if RLS
        # unexpectedly allows both rows to be modified.
        update_stmt = sqlalchemy.text(
            "UPDATE users SET username = 'twophase_' || id::text"
        )
        rls_sess = session.RlsSession(
            context=models.SampleRlsContext(account_id=1),
            bind=self.engine,
            twophase=True,
        )
        rls_sess_acct2 = session.RlsSession(
            context=models.SampleRlsContext(account_id=2),
            bind=self.engine,
        )
        try:
            with rls_sess.begin():
                # RLS limits the UPDATE to the row where id = 1.
                rows_updated = rls_sess.execute(update_stmt).rowcount
                self.assertEqual(rows_updated, 1)
                rls_sess.prepare()  # First phase of two-phase commit
                rls_sess.commit()  # Second phase of two-phase commit
            with rls_sess.begin():
                # No WHERE clause: RLS restricts the result to account_id=1.
                usernames = list(
                    rls_sess.execute(
                        sqlalchemy.text("SELECT username FROM users")
                    ).scalars()
                )
            self.assertEqual(usernames, ["twophase_1"])
            # Verify account_id=2's row was not affected by the UPDATE.
            with rls_sess_acct2.begin():
                usernames_acct2 = list(
                    rls_sess_acct2.execute(
                        sqlalchemy.text("SELECT username FROM users")
                    ).scalars()
                )
            self.assertEqual(usernames_acct2, ["user2"])
        finally:
            rls_sess.close()
            rls_sess_acct2.close()
            with self.instance.admin_engine.connect() as conn, conn.begin():
                conn.execute(
                    sqlalchemy.text("UPDATE users SET username = 'user1' WHERE id = 1")
                )


def _detached_user(rls_sess: session.RlsSession, user_id: int) -> models.User:
    """Attach a persistent User without loading it, so the next database
    access is the UPDATE issued by flush()."""
    user = models.User(id=user_id, username=f"user{user_id}")
    orm.make_transient_to_detached(user)
    rls_sess.add(user)
    return user


class SyncRLSRegressionTests(unittest.TestCase):
    """Regression tests for RLS settings leaking or not being applied."""

    instance: database.TestPostgres
    engine: sqlalchemy.engine.Engine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        # A single pooled connection makes connection reuse deterministic.
        cls.engine = sqlalchemy.create_engine(
            cls.instance.url, pool_size=1, max_overflow=0
        )

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.instance.close()

    def _use_account(self, account_id: int) -> None:
        """Run a query as account_id and return the connection to the pool."""
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=account_id), bind=self.engine
        ) as rls_sess:
            self.assertEqual(rls_sess.execute(_USER_ID_QUERY).scalars().all(), [1])
            rls_sess.commit()

    def _count_set_config(self) -> list[str]:
        statements: list[str] = []

        def listener(conn, cursor, statement, parameters, context, executemany):
            if "set_config" in statement:
                statements.append(statement)

        sqlalchemy.event.listen(self.engine, "before_cursor_execute", listener)
        self.addCleanup(
            sqlalchemy.event.remove, self.engine, "before_cursor_execute", listener
        )
        return statements

    def test_settings_do_not_leak_to_none_context_session(self):
        """A pooled connection must not carry a previous session's context."""
        self._use_account(1)
        with session.RlsSession(context=None, bind=self.engine) as rls_sess:
            self.assertEqual(rls_sess.execute(_USER_ID_QUERY).scalars().all(), [])

    def test_settings_do_not_leak_to_plain_connection(self):
        """Nothing remains set on a connection after it returns to the pool."""
        self._use_account(1)
        with self.engine.connect() as conn:
            value = conn.execute(
                sqlalchemy.text("SELECT current_setting('rls.account_id', true)")
            ).scalar()
            self.assertIn(value, ("", None))

    def test_flush_uses_current_context_on_reused_connection(self):
        """An ORM flush must run with the session's own context."""
        self._use_account(1)
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=2), bind=self.engine
        ) as rls_sess:
            user = _detached_user(rls_sess, 1)
            user.username = "hijacked"
            # Account 2 cannot see user 1, so the UPDATE matches no rows.
            with self.assertRaises(orm.exc.StaleDataError):
                rls_sess.flush()

    def test_flush_inside_bypass_applies_bypass(self):
        """A flush inside bypass_rls() runs with RLS bypassed."""
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=2), bind=self.engine
        ) as rls_sess:
            rls_sess.execute(_NOOP_QUERY)
            with rls_sess.bypass_rls():
                user = _detached_user(rls_sess, 1)
                user.username = "bypassed"
                rls_sess.flush()
            rls_sess.rollback()

    def test_flush_uses_mutated_context(self):
        """A flush after mutating the context runs with the new context."""
        context = models.SampleRlsContext(account_id=2)
        with session.RlsSession(context=context, bind=self.engine) as rls_sess:
            rls_sess.execute(_NOOP_QUERY)
            context.account_id = 1
            user = _detached_user(rls_sess, 1)
            user.username = "mutated"
            rls_sess.flush()
            rls_sess.rollback()

    def test_get_applies_context(self):
        """Session.get() runs with the session's context."""
        self._use_account(1)
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=2), bind=self.engine
        ) as rls_sess:
            self.assertIsNone(rls_sess.get(models.User, 1))
            user = rls_sess.get(models.User, 2)
            self.assertIsNotNone(user)

    def test_connection_applies_context(self):
        """Statements run on session.connection() use the session's context."""
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=2), bind=self.engine
        ) as rls_sess:
            conn = rls_sess.connection()
            self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [2])
            with rls_sess.bypass_rls():
                conn = rls_sess.connection()
                self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [1, 2])

    def test_connection_sees_bypass_enter_and_exit(self):
        """Raw statements on an existing connection follow bypass_rls()."""
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=1), bind=self.engine
        ) as rls_sess:
            conn = rls_sess.connection()
            self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [1])
            with rls_sess.bypass_rls():
                self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [1, 2])
            self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [1])

    def test_connection_sees_mutated_context(self):
        """Raw statements on an existing connection see context mutations."""
        context = models.SampleRlsContext(account_id=1)
        with session.RlsSession(context=context, bind=self.engine) as rls_sess:
            conn = rls_sess.connection()
            self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [1])
            context.account_id = 2
            self.assertEqual(conn.execute(_USER_ID_QUERY).scalars().all(), [2])

    def test_connection_no_extra_set_config(self):
        """Repeated raw statements do not re-send unchanged settings."""
        statements = self._count_set_config()
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=1), bind=self.engine
        ) as rls_sess:
            conn = rls_sess.connection()
            self.assertEqual(rls_sess.connection(), conn)
            for _ in range(3):
                conn.execute(_USER_ID_QUERY)
            rls_sess.execute(_USER_ID_QUERY)
            self.assertEqual(len(statements), 1)

    def test_connection_listener_removed_after_transaction(self):
        """No listener or session reference remains after commit or rollback."""
        for end in ("commit", "rollback"):
            with (
                self.subTest(end=end),
                session.RlsSession(
                    context=models.SampleRlsContext(account_id=1), bind=self.engine
                ) as rls_sess,
            ):
                conn = rls_sess.connection()
                self.assertTrue(
                    sqlalchemy.event.contains(
                        conn, "before_execute", rls_sess._rls_before_execute
                    )
                )
                getattr(rls_sess, end)()
                self.assertFalse(
                    sqlalchemy.event.contains(
                        conn, "before_execute", rls_sess._rls_before_execute
                    )
                )
                self.assertEqual(rls_sess._rls_listened_connections, [])

    def test_settings_applied_once_per_transaction(self):
        """Repeated statements in one transaction do not re-send settings."""
        statements = self._count_set_config()
        with session.RlsSession(
            context=models.ImmutableSampleRlsContext(account_id=1), bind=self.engine
        ) as rls_sess:
            for _ in range(3):
                rls_sess.execute(_USER_ID_QUERY)
            rls_sess.get(models.User, 1)
            self.assertEqual(len(statements), 1)
            rls_sess.commit()
            rls_sess.execute(_USER_ID_QUERY)
            rls_sess.execute(_USER_ID_QUERY)
            self.assertEqual(len(statements), 2)

    def test_mutable_context_settings_applied_only_on_change(self):
        """A mutable context only re-sends settings when it actually changes."""
        statements = self._count_set_config()
        context = models.SampleRlsContext(account_id=1)
        with session.RlsSession(context=context, bind=self.engine) as rls_sess:
            rls_sess.execute(_USER_ID_QUERY)
            rls_sess.execute(_USER_ID_QUERY)
            self.assertEqual(len(statements), 1)
            context.account_id = 2
            self.assertEqual(rls_sess.execute(_USER_ID_QUERY).scalars().all(), [2])
            rls_sess.execute(_USER_ID_QUERY)
            self.assertEqual(len(statements), 2)

    def test_savepoint_rollback_reapplies_settings(self):
        """Rolling back a savepoint re-applies the settings it reverted."""
        with session.RlsSession(
            context=models.SampleRlsContext(account_id=1), bind=self.engine
        ) as rls_sess:
            savepoint = rls_sess.begin_nested()
            self.assertEqual(rls_sess.execute(_USER_ID_QUERY).scalars().all(), [1])
            savepoint.rollback()
            self.assertEqual(rls_sess.execute(_USER_ID_QUERY).scalars().all(), [1])


_RLS_VIOLATION = "row-level security"


class SyncRLSWriteTests(unittest.TestCase):
    """ORM writes (INSERT/UPDATE/DELETE) are checked against the policies."""

    instance: database.TestPostgres
    engine: sqlalchemy.engine.Engine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        # A single pooled connection makes connection reuse deterministic.
        cls.engine = sqlalchemy.create_engine(
            cls.instance.url, pool_size=1, max_overflow=0
        )

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.instance.close()

    def _new_session(self, account_id: int) -> session.RlsSession:
        return session.RlsSession(
            context=models.SampleRlsContext(account_id=account_id), bind=self.engine
        )

    def test_orm_insert_allowed_by_with_check(self):
        with self._new_session(1) as rls_sess:
            item = models.Item(title="new", owner_id=1)
            rls_sess.add(item)
            rls_sess.flush()
            self.assertIsNotNone(item.id)
            rls_sess.rollback()

    def test_orm_insert_rejected_by_with_check(self):
        with self._new_session(1) as rls_sess:
            rls_sess.add(models.Item(title="new", owner_id=2))
            with self.assertRaisesRegex(
                sqlalchemy.exc.ProgrammingError, _RLS_VIOLATION
            ):
                rls_sess.flush()

    def test_orm_insert_uses_own_context_on_reused_connection(self):
        """An INSERT on a pooled connection is checked with the new context."""
        with self._new_session(2) as rls_sess:
            rls_sess.add(models.Item(title="new", owner_id=2))
            rls_sess.flush()
            rls_sess.commit()
        with self._new_session(1) as rls_sess:
            rls_sess.add(models.Item(title="new", owner_id=2))
            with self.assertRaisesRegex(
                sqlalchemy.exc.ProgrammingError, _RLS_VIOLATION
            ):
                rls_sess.flush()
        with self.instance.admin_engine.begin() as conn:
            conn.execute(sqlalchemy.text("DELETE FROM items WHERE title = 'new'"))

    def test_orm_update_rejected_by_with_check(self):
        """Moving a visible row out of the account fails the WITH CHECK."""
        with self._new_session(1) as rls_sess:
            item = rls_sess.scalars(
                sqlalchemy.select(models.Item).where(models.Item.owner_id == 1)
            ).first()
            assert item is not None
            item.owner_id = 2
            with self.assertRaisesRegex(
                sqlalchemy.exc.ProgrammingError, _RLS_VIOLATION
            ):
                rls_sess.flush()

    def test_delete_only_affects_visible_rows(self):
        with self._new_session(2) as rls_sess:
            result = rls_sess.execute(
                sqlalchemy.delete(models.User).where(models.User.id == 1)
            )
            self.assertEqual(typing.cast(sqlalchemy.CursorResult, result).rowcount, 0)
            rls_sess.rollback()

    def test_bypass_allows_insert(self):
        with self._new_session(1) as rls_sess:
            with rls_sess.bypass_rls():
                rls_sess.add(models.Item(title="bypass", owner_id=2))
                rls_sess.flush()
            rls_sess.rollback()


_SCHEMA = "rls_runtime"
_OTHER_ROLE = "rls_other_role"
_FORBIDDEN_TITLE = "forbidden"


class _SchemaBase(orm.DeclarativeBase):
    pass


register.base_wrapper(_SchemaBase, context_model=models.SampleRlsContext)


def _account_arg() -> list[policy.ConditionArg]:
    return [policy.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer)]


class _Doc(_SchemaBase):
    __tablename__ = "docs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: orm.Mapped[int] = orm.mapped_column(sqlalchemy.Integer, primary_key=True)
    owner_id: orm.Mapped[int] = orm.mapped_column(sqlalchemy.Integer)
    title: orm.Mapped[str] = orm.mapped_column(sqlalchemy.String)

    __rls_policies__: typing.ClassVar[list[policy.Policy]] = [
        policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.column("owner_id") == x,
            condition_args=_account_arg(),
            cmd=policy.Command.select,
            roles=["test_user"],
        ),
        # Would expose every row, but only applies to another role.
        policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.column("owner_id") >= 0,
            condition_args=_account_arg(),
            cmd=policy.Command.select,
            roles=[_OTHER_ROLE],
        ),
        policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.column("owner_id") == x,
            condition_args=_account_arg(),
            cmd=policy.Command.insert,
        ),
        policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.column("owner_id") == x,
            check_expr=lambda x: sqlalchemy.and_(
                sqlalchemy.column("owner_id") == x,
                sqlalchemy.column("title") != _FORBIDDEN_TITLE,
            ),
            condition_args=_account_arg(),
            cmd=policy.Command.update,
        ),
    ]


class SyncRLSSchemaRolesTests(unittest.TestCase):
    """Policies on a schema-qualified table, with roles and a separate WITH
    CHECK expression, enforced at runtime for a non-superuser."""

    instance: database.TestPostgres
    engine: sqlalchemy.engine.Engine

    @classmethod
    def setUpClass(cls):
        cls.instance = database.test_postgres_instance()
        with cls.instance.admin_engine.begin() as conn:
            conn.execute(sqlalchemy.text(f"CREATE SCHEMA {_SCHEMA}"))
            conn.execute(sqlalchemy.text(f"CREATE ROLE {_OTHER_ROLE}"))
            _SchemaBase.metadata.create_all(conn)
            create_policies.create_policies_no_commit(_SchemaBase, conn)
            conn.execute(
                sqlalchemy.insert(_Doc).values(
                    [
                        {"id": 1, "owner_id": 1, "title": "one"},
                        {"id": 2, "owner_id": 2, "title": "two"},
                    ]
                )
            )
            conn.execute(
                sqlalchemy.text(f"GRANT USAGE ON SCHEMA {_SCHEMA} TO test_user")
            )
            conn.execute(
                sqlalchemy.text(
                    f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.docs TO test_user"
                )
            )
        cls.engine = sqlalchemy.create_engine(cls.instance.url)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.instance.close()

    def _new_session(self, account_id: int) -> session.RlsSession:
        return session.RlsSession(
            context=models.SampleRlsContext(account_id=account_id), bind=self.engine
        )

    def test_policies_stored_with_roles_and_check(self):
        with self.instance.admin_engine.connect() as conn:
            rows = conn.execute(
                sqlalchemy.text(
                    "SELECT cmd, roles::text[], qual IS NOT NULL, with_check "
                    "FROM pg_policies WHERE schemaname = :s AND tablename = 'docs'"
                ),
                {"s": _SCHEMA},
            ).all()
        by_cmd: dict[str, list] = {}
        for cmd, roles, has_qual, with_check in rows:
            by_cmd.setdefault(cmd, []).append((roles, has_qual, with_check))
        self.assertCountEqual(
            [roles for roles, _, _ in by_cmd["SELECT"]],
            [["test_user"], [_OTHER_ROLE]],
        )
        ((roles, has_qual, with_check),) = by_cmd["UPDATE"]
        self.assertEqual(roles, ["public"])
        self.assertTrue(has_qual)
        self.assertIn(_FORBIDDEN_TITLE, with_check)

    def test_select_only_applies_policies_for_current_role(self):
        for account_id in (1, 2):
            with (
                self.subTest(account_id=account_id),
                self._new_session(account_id) as rls_sess,
            ):
                ids = rls_sess.scalars(sqlalchemy.select(_Doc.id)).all()
                self.assertEqual(ids, [account_id])

    def test_get_on_schema_table(self):
        with self._new_session(1) as rls_sess:
            self.assertIsNotNone(rls_sess.get(_Doc, 1))
            self.assertIsNone(rls_sess.get(_Doc, 2))

    def test_insert_on_schema_table(self):
        with self._new_session(1) as rls_sess:
            rls_sess.add(_Doc(id=10, owner_id=1, title="ten"))
            rls_sess.flush()
            rls_sess.rollback()
            rls_sess.add(_Doc(id=11, owner_id=2, title="eleven"))
            with self.assertRaisesRegex(
                sqlalchemy.exc.ProgrammingError, _RLS_VIOLATION
            ):
                rls_sess.flush()

    def test_update_allowed_by_separate_check(self):
        with self._new_session(1) as rls_sess:
            doc = rls_sess.get(_Doc, 1)
            assert doc is not None
            doc.title = "renamed"
            rls_sess.flush()
            rls_sess.rollback()

    def test_update_rejected_by_separate_check(self):
        """The row passes USING but the new row fails the WITH CHECK."""
        with self._new_session(1) as rls_sess:
            doc = rls_sess.get(_Doc, 1)
            assert doc is not None
            doc.title = _FORBIDDEN_TITLE
            with self.assertRaisesRegex(
                sqlalchemy.exc.ProgrammingError, _RLS_VIOLATION
            ):
                rls_sess.flush()


if __name__ == "__main__":
    unittest.main()
