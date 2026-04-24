import contextlib

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio


def _is_context_immutable(context: pydantic.BaseModel | None) -> bool:
    if context is None:
        return True
    model_config = getattr(type(context), "model_config", None)
    if model_config is None:
        return False
    return bool(model_config.get("frozen"))


def _context_to_value_params(
    context: pydantic.BaseModel | None, keys: list[str]
) -> dict[str, str]:
    if context is None or not keys:
        return {}
    return {
        f"value_{key}": "" if (x := getattr(context, key)) is None else str(x)
        for key in keys
    }


def _set_statement_template(keys: list[str]) -> sqlalchemy.Select:
    """
    Pre-computes the SQL template for setting RLS config values at init time.

    The SQLAlchemy select() expression with literal setting names and named
    bind parameters for the values is built once and stored.  Each call to
    _get_set_statement() then only needs to substitute the current field
    values into this template, which is significantly cheaper than rebuilding
    the entire statement every time.
    """
    set_config_calls = [
        sqlalchemy.func.set_config(
            sqlalchemy.literal("rls.bypass_rls"),
            sqlalchemy.literal("false"),
            sqlalchemy.false(),
        )
    ]
    for key in keys:
        if key == "bypass_rls":
            raise ValueError("Context field names cannot be 'bypass_rls'")
        # Bind parameters are named after the field (e.g. setting_account_id,
        # value_account_id) so the mapping is explicit and not order-dependent.
        set_config_calls.append(
            sqlalchemy.func.set_config(
                sqlalchemy.literal(f"rls.{key}"),
                sqlalchemy.bindparam(f"value_{key}"),
                sqlalchemy.false(),
            )
        )
    return sqlalchemy.select(*set_config_calls)


class _RlsSessionMixin:
    """Shared logic for RlsSession and AsyncRlsSession."""

    def __init__(self, context: pydantic.BaseModel | None = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rls_bypass_depth = 0  # Track RLS bypass nesting depth
        self._rls_dirty = True
        self._rls_last_set_context_snapshot: pydantic.BaseModel | None = None
        self._context = context
        self._rls_context_is_immutable = _is_context_immutable(context)
        self._rls_context_keys: list[str] = (
            list(type(self._context).model_fields.keys()) if self._context else []
        )
        self._rls_set_template = _set_statement_template(self._rls_context_keys)

    def _get_set_statement(self) -> sqlalchemy.ClauseElement | None:
        """
        Returns the SQL statement to set all RLS config values.

        The SQL template was pre-computed at init time; here we only substitute
        the current field values.  None values are stored as an empty string so
        that the RLS policy expressions (which wrap current_setting() with
        NULLIF(..., '')) treat them as NULL and filter out all rows.
        """
        if self._rls_bypass_depth > 0:
            if self._rls_dirty:
                return sqlalchemy.text("SET LOCAL rls.bypass_rls = true;")
            return None
        if not self._rls_dirty:
            if self._rls_context_is_immutable:
                return None
            if self._context == self._rls_last_set_context_snapshot:
                return None
        self._rls_last_set_context_snapshot = (
            self._context.model_copy(deep=True) if self._context else None
        )
        value_params = _context_to_value_params(
            self._rls_last_set_context_snapshot, self._rls_context_keys
        )
        return self._rls_set_template.params(**value_params)


class BypassRLSContext:
    def __init__(self, session: "RlsSession"):
        self.session = session

    def __enter__(self):
        is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if is_outermost:
            self.session._rls_dirty = True
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        is_outermost = self.session._rls_bypass_depth == 0
        if exc_type is not None and is_outermost:
            self.session.rollback()
            self.session._rls_bypass_depth = 0
        if is_outermost:
            self.session._rls_dirty = True


class AsyncBypassRLSContext:
    def __init__(self, session: "AsyncRlsSession"):
        self.session = session

    async def __aenter__(self):
        is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if is_outermost:
            self.session._rls_dirty = True
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        is_outermost = self.session._rls_bypass_depth == 0
        if exc_type is not None and is_outermost:
            await self.session.rollback()
            self.session._rls_bypass_depth = 0
        if is_outermost:
            self.session._rls_dirty = True


class RlsSession(_RlsSessionMixin, orm.Session):
    def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if (stmt := self._get_set_statement()) is not None:
            super().execute(stmt)
            self._rls_dirty = False

    @contextlib.contextmanager
    def begin(self):
        with super().begin():
            self._execute_set_statements()
            yield self

    def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        self._execute_set_statements()
        return super().execute(*args, **kwargs)

    def scalar(self, *args, **kwargs):
        """
        Executes a statement and returns a scalar result, applying RLS unless bypassing.
        """
        self._execute_set_statements()
        return super().scalar(*args, **kwargs)

    def scalars(self, *args, **kwargs):
        """
        Executes a statement and returns scalar results, applying RLS unless bypassing.
        """
        self._execute_set_statements()
        return super().scalars(*args, **kwargs)

    def commit(self):
        super().commit()
        self._rls_dirty = True

    def rollback(self):
        super().rollback()
        self._rls_dirty = True

    def bypass_rls(self) -> BypassRLSContext:
        return BypassRLSContext(self)


class AsyncRlsSession(_RlsSessionMixin, sa_asyncio.AsyncSession):
    async def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if (stmt := self._get_set_statement()) is not None:
            await super().execute(stmt)
            self._rls_dirty = False

    @contextlib.asynccontextmanager
    async def begin(self):
        async with super().begin():
            await self._execute_set_statements()
            yield self

    async def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        await self._execute_set_statements()
        return await super().execute(*args, **kwargs)

    async def scalar(self, *args, **kwargs):
        """
        Executes a statement and returns a scalar result, applying RLS unless bypassing.
        """
        await self._execute_set_statements()
        return await super().scalar(*args, **kwargs)

    async def scalars(self, *args, **kwargs):
        """
        Executes a statement and returns scalar results, applying RLS unless bypassing.
        """
        await self._execute_set_statements()
        return await super().scalars(*args, **kwargs)

    async def commit(self):
        await super().commit()
        self._rls_dirty = True

    async def rollback(self):
        await super().rollback()
        self._rls_dirty = True

    def bypass_rls(self) -> AsyncBypassRLSContext:
        return AsyncBypassRLSContext(self)
