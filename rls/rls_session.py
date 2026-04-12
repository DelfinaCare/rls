from typing import Optional

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio


class _RlsSessionMixin:
    """Shared logic for RlsSession and AsyncRlsSession."""

    def __init__(self, context: Optional[pydantic.BaseModel] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rls_bypass = False  # Track RLS bypass state
        if context is not None:
            self.context = context

    def _get_set_statements(self):
        """
        Generates SQL SET statements based on the context model.

        Uses set_config() with bound parameters to prevent SQL injection from
        values passed through the context.
        """
        stmts = []
        if self.context is None or self._rls_bypass:  # Skip RLS statements if bypassed
            return None

        for key, value in self.context.model_dump().items():
            stmt = sqlalchemy.text(
                "SELECT set_config(:setting, :value, false)"
            ).bindparams(
                setting=f"rls.{key}",
                value=str(value) if value is not None else "",
            )
            stmts.append(stmt)
        return stmts


class BypassRLSContext:
    def __init__(self, session: "RlsSession"):
        self.session = session

    def __enter__(self):
        self.session._rls_bypass = True
        self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = true;"))
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass = False
        if exc_type is not None:
            self.session.rollback()
            return
        self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = false;"))

    def execute(self, *args, **kwargs):
        return self.session.execute(*args, **kwargs)


class RlsSession(_RlsSessionMixin, orm.Session):
    def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if self._rls_bypass:  # Skip setting RLS when bypassing
            return
        stmts = self._get_set_statements()
        if stmts is not None:
            for stmt in stmts:
                super().execute(stmt)

    def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        self._execute_set_statements()
        return super().execute(*args, **kwargs)

    def bypass_rls(self) -> BypassRLSContext:
        return BypassRLSContext(self)


class AsyncBypassRLSContext:
    def __init__(self, session: "AsyncRlsSession"):
        self.session = session

    async def __aenter__(self):
        self.session._rls_bypass = True
        await self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = true;"))
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass = False
        if exc_type is not None:
            await self.session.rollback()
            return
        await self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = false;"))


class AsyncRlsSession(_RlsSessionMixin, sa_asyncio.AsyncSession):
    async def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if self._rls_bypass:  # Skip setting RLS when bypassing
            return
        stmts = self._get_set_statements()
        if stmts is not None:
            for stmt in stmts:
                await super().execute(stmt)

    async def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        await self._execute_set_statements()
        return await super().execute(*args, **kwargs)

    def bypass_rls(self) -> AsyncBypassRLSContext:
        return AsyncBypassRLSContext(self)
