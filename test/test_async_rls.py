import pytest
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import rls_session
from test import database, models


async def get_pg_rls_setting(
    session: rls_session.AsyncRlsSession, setting_name: str
) -> str:
    """Reads a PostgreSQL RLS session setting value."""
    result = await session.execute(
        sqlalchemy.text(f"SELECT current_setting('rls.{setting_name}', true);")
    )
    return result.scalar()


@pytest.fixture(scope="module")
def db_instance():
    inst = database.test_postgres_instance()
    yield inst
    del inst


@pytest.fixture
def async_engine(db_instance):
    return db_instance.async_non_superadmin_engine


def new_async_session(
    engine: sa_asyncio.AsyncEngine, account_id: int = 1
) -> rls_session.AsyncRlsSession:
    return rls_session.AsyncRlsSession(
        context=models.SampleRlsContext(account_id=account_id),
        bind=engine,
    )


class TestAsyncRLSPolicies:
    @pytest.mark.asyncio
    async def test_rls_query_with_async_rls_session(self, async_engine):
        """AsyncRlsSession applies RLS and returns only the matching user."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=async_engine)
        async with rls_sess.begin():
            result = await rls_sess.execute(sqlalchemy.text("SELECT * FROM users;"))
            users = result.mappings().fetchall()
            assert len(users) == 1
            assert users[0]["id"] == 1
            assert users[0]["username"] == "user1"

    @pytest.mark.asyncio
    async def test_rls_query_with_async_rls_session_and_bypass(self, async_engine):
        """AsyncRlsSession with bypass_rls returns all users."""
        context = models.SampleRlsContext(account_id=1)
        rls_sess = rls_session.AsyncRlsSession(context=context, bind=async_engine)
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                result = await rls_sess.execute(sqlalchemy.text("SELECT * FROM users;"))
                users = result.mappings().fetchall()
                assert len(users) == 2


class TestAsyncRLSSessionBehavior:
    @pytest.mark.asyncio
    async def test_bypass_rls_default_false(self, async_engine):
        """bypass_rls pg setting is falsy before entering a bypass context."""
        rls_sess = new_async_session(async_engine)
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            assert setting in {"", None, "false"}
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_bypass_rls_active_inside_context(self, async_engine):
        """bypass_rls pg setting is 'true' while inside the bypass_rls context."""
        rls_sess = new_async_session(async_engine)
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
                assert setting == "true"
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_bypass_rls_restored_after_exit(self, async_engine):
        """bypass_rls pg setting is restored to false after exiting the context."""
        rls_sess = new_async_session(async_engine)
        async with rls_sess.begin():
            async with rls_sess.bypass_rls():
                pass
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            assert setting in {"", None, "false"}
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_exception_during_bypass_propagates(self, async_engine):
        """Exceptions raised inside bypass_rls propagate to the caller."""
        rls_sess = new_async_session(async_engine)
        with pytest.raises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_exception_without_bypass_propagates(self, async_engine):
        """Exceptions raised outside bypass_rls propagate to the caller."""
        rls_sess = new_async_session(async_engine)
        with pytest.raises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_sql_exception_during_bypass_restores_state(self, async_engine):
        """After a SQL exception inside bypass_rls, bypass state is cleared."""
        rls_sess = new_async_session(async_engine)
        with pytest.raises(sqlalchemy.exc.DataError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    await rls_sess.execute(sqlalchemy.text("SELECT 1/0;"))
        # _rls_bypass flag must be cleared regardless of exception
        assert not rls_sess._rls_bypass
        # A new transaction should see no bypass
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            assert setting in {"", None, "false"}
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_python_exception_during_bypass_restores_state(self, async_engine):
        """After a Python exception inside bypass_rls, bypass state is cleared."""
        rls_sess = new_async_session(async_engine)
        with pytest.raises(ValueError):
            async with rls_sess.begin():
                async with rls_sess.bypass_rls():
                    raise ValueError("Test")
        assert not rls_sess._rls_bypass
        async with rls_sess.begin():
            setting = await get_pg_rls_setting(rls_sess, "bypass_rls")
            assert setting in {"", None, "false"}
        await rls_sess.close()

    @pytest.mark.asyncio
    async def test_different_contexts_see_different_data(self, async_engine):
        """Sessions created with different account_ids each see only their own user."""
        rls_sess1 = new_async_session(async_engine, account_id=1)
        rls_sess2 = new_async_session(async_engine, account_id=2)
        async with rls_sess1.begin():
            async with rls_sess2.begin():
                result1 = (
                    (await rls_sess1.execute(sqlalchemy.text("SELECT * FROM users")))
                    .mappings()
                    .fetchall()
                )
                result2 = (
                    (await rls_sess2.execute(sqlalchemy.text("SELECT * FROM users")))
                    .mappings()
                    .fetchall()
                )
                assert len(result1) == 1
                assert result1[0]["id"] == 1
                assert len(result2) == 1
                assert result2[0]["id"] == 2
        await rls_sess1.close()
        await rls_sess2.close()
