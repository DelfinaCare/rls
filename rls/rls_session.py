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
        Generates SQL statements to set all RLS config values.

        Non-None values are combined into a single SELECT set_config() statement
        with bound parameters to prevent SQL injection.  None values emit a RESET
        statement for their GUC, so current_setting(key, true) returns NULL and the
        RLS policy expression evaluates to NULL (i.e. no rows are returned).
        """
        if self.context is None or self._rls_bypass:  # Skip RLS statements if bypassed
            return []

        items = list(self.context.model_dump().items())
        if not items:
            return []

        stmts = []
        set_parts = []
        set_params = {}
        set_idx = 0

        for key, value in items:
            if value is not None:
                # User-supplied values are passed exclusively through bound
                # parameters to prevent SQL injection.
                set_parts.append(
                    f"set_config(:setting_{set_idx}, :value_{set_idx}, false)"
                )
                set_params[f"setting_{set_idx}"] = f"rls.{key}"
                set_params[f"value_{set_idx}"] = str(value)
                set_idx += 1
            else:
                # RESET removes the GUC from the session; current_setting(key, true)
                # then returns NULL, so the policy expression filters out all rows.
                # key is a pydantic model field name (code-defined, not user input).
                stmts.append(sqlalchemy.text(f"RESET rls.{key}"))

        if set_parts:
            stmts.insert(
                0,
                sqlalchemy.text(f"SELECT {', '.join(set_parts)}").bindparams(
                    **set_params
                ),
            )

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
        for stmt in self._get_set_statements():
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
        for stmt in self._get_set_statements():
            await super().execute(stmt)

    async def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        await self._execute_set_statements()
        return await super().execute(*args, **kwargs)

    def bypass_rls(self) -> AsyncBypassRLSContext:
        return AsyncBypassRLSContext(self)
