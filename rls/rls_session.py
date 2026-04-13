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
        self._rls_set_template: Optional[sqlalchemy.TextClause] = None
        self._rls_context_keys: list[str] = []
        if context is not None:
            self.context = context
            self._precompute_set_template()

    def _precompute_set_template(self) -> None:
        """
        Pre-computes the SQL template for setting RLS config values at init time.

        The SQL text and static setting-name bind parameters (rls.<field>) are
        built once and stored.  Each call to _get_set_statements() then only
        needs to substitute the current field values into this template, which
        is significantly cheaper than rebuilding the entire statement every time.
        """
        keys = list(self.context.model_fields.keys())
        if not keys:
            return

        set_parts = []
        static_params: dict[str, str] = {}
        for idx, key in enumerate(keys):
            set_parts.append(f"set_config(:setting_{idx}, :value_{idx}, false)")
            static_params[f"setting_{idx}"] = f"rls.{key}"

        self._rls_context_keys = keys
        self._rls_set_template = sqlalchemy.text(
            f"SELECT {', '.join(set_parts)}"
        ).bindparams(**static_params)

    def _get_set_statements(self):
        """
        Returns a single SQL statement to set all RLS config values.

        The SQL template was pre-computed at init time; here we only substitute
        the current field values.  None values are stored as an empty string so
        that the RLS policy expressions (which wrap current_setting() with
        NULLIF(..., '')) treat them as NULL and filter out all rows.
        """
        if self.context is None or self._rls_bypass or self._rls_set_template is None:
            return []

        # Only value substitution happens here — the template and setting-name
        # parameters were already bound during _precompute_set_template().
        value_params = {
            f"value_{idx}": "" if getattr(self.context, key) is None else str(getattr(self.context, key))
            for idx, key in enumerate(self._rls_context_keys)
        }
        return [self._rls_set_template.bindparams(**value_params)]


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
