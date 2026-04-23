import contextlib
import typing

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio


class _HasTransaction(typing.Protocol):
    def get_transaction(self) -> typing.Any: ...


class _RlsSessionMixin:
    """Shared logic for RlsSession and AsyncRlsSession."""

    def __init__(self, context: pydantic.BaseModel | None = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rls_bypass_depth = 0  # Track RLS bypass nesting depth
        self._rls_needs_bypass_reapply = False  # Set after commit while in bypass
        self._rls_set_template: sqlalchemy.Select | None = None
        self._rls_context_keys: list[str] = []
        self._rls_last_set_context_state: pydantic.BaseModel | None = None
        self._rls_last_context_transaction_id: int | None = None
        self.context = context
        if context is not None:
            self._precompute_set_template()

    @property
    def _rls_bypass(self) -> bool:
        return self._rls_bypass_depth > 0

    def _precompute_set_template(self) -> None:
        """
        Pre-computes the SQL template for setting RLS config values at init time.

        The SQLAlchemy select() expression with literal setting names and named
        bind parameters for the values is built once and stored.  Each call to
        _get_set_statements() then only needs to substitute the current field
        values into this template, which is significantly cheaper than rebuilding
        the entire statement every time.
        """
        if self.context is None:
            raise ValueError("_precompute_set_template called with no context")
        keys = list(type(self.context).model_fields.keys())
        if not keys:
            return

        set_config_calls = []
        for key in keys:
            # Bind parameters are named after the field (e.g. setting_account_id,
            # value_account_id) so the mapping is explicit and not order-dependent.
            set_config_calls.append(
                sqlalchemy.func.set_config(
                    sqlalchemy.literal(f"rls.{key}"),
                    sqlalchemy.bindparam(f"value_{key}"),
                    sqlalchemy.false(),
                )
            )

        self._rls_context_keys = keys
        self._rls_set_template = sqlalchemy.select(*set_config_calls)

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

        current_transaction_id = self._get_current_transaction_id()
        has_applied_context = self._rls_last_set_context_state is not None
        needs_reapply_for_transaction = (
            not has_applied_context
            or current_transaction_id != self._rls_last_context_transaction_id
        )

        if (
            not needs_reapply_for_transaction
            and self.context == self._rls_last_set_context_state
        ):
            return []

        # Only value substitution happens here — the template with literal setting
        # names was already built during _precompute_set_template().
        value_params = self._get_current_context_value_params()

        self._rls_last_set_context_state = (
            None if self.context is None else self.context.model_copy(deep=True)
        )
        return [self._rls_set_template.params(**value_params)]

    def _get_current_context_value_params(self) -> dict[str, str]:
        if self.context is None:
            return {}
        return {
            f"value_{key}": (
                ""
                if getattr(self.context, key) is None
                else str(getattr(self.context, key))
            )
            for key in self._rls_context_keys
        }

    def _get_current_transaction_id(self) -> int | None:
        transaction = typing.cast(_HasTransaction, self).get_transaction()
        return None if transaction is None else id(transaction)

    def _mark_context_applied_to_current_transaction(self) -> None:
        self._rls_last_context_transaction_id = self._get_current_transaction_id()


class BypassRLSContext:
    def __init__(self, session: "RlsSession"):
        self.session = session
        self._is_outermost = False

    def __enter__(self):
        self._is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if self._is_outermost:
            self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = true;"))
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        if exc_type is not None:
            if self._is_outermost:
                self.session._rls_bypass_depth = 0
                self.session._rls_needs_bypass_reapply = False
                self.session.rollback()
            return
        if self._is_outermost:
            self.session._rls_needs_bypass_reapply = False
            self.session.execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = false;"))

    def execute(self, *args, **kwargs):
        return self.session.execute(*args, **kwargs)


class RlsSession(_RlsSessionMixin, orm.Session):
    def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if self._rls_bypass:
            # Re-apply the bypass flag if a commit cleared it since the last command.
            if self._rls_needs_bypass_reapply:
                self._rls_needs_bypass_reapply = False
                super().execute(sqlalchemy.text("SET LOCAL rls.bypass_rls = true;"))
            # Always skip normal RLS context settings when bypassing.
            return
        set_statements = self._get_set_statements()
        for stmt in set_statements:
            super().execute(stmt)
        if set_statements:
            self._mark_context_applied_to_current_transaction()

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
        if self._rls_bypass:
            self._rls_needs_bypass_reapply = True

    def bypass_rls(self) -> BypassRLSContext:
        return BypassRLSContext(self)


class AsyncBypassRLSContext:
    def __init__(self, session: "AsyncRlsSession"):
        self.session = session
        self._is_outermost = False

    async def __aenter__(self):
        self._is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if self._is_outermost:
            await self.session.execute(
                sqlalchemy.text("SET LOCAL rls.bypass_rls = true;")
            )
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        if exc_type is not None:
            if self._is_outermost:
                self.session._rls_bypass_depth = 0
                self.session._rls_needs_bypass_reapply = False
                await self.session.rollback()
            return
        if self._is_outermost:
            self.session._rls_needs_bypass_reapply = False
            await self.session.execute(
                sqlalchemy.text("SET LOCAL rls.bypass_rls = false;")
            )


class AsyncRlsSession(_RlsSessionMixin, sa_asyncio.AsyncSession):
    async def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if self._rls_bypass:
            # Re-apply the bypass flag if a commit cleared it since the last command.
            if self._rls_needs_bypass_reapply:
                self._rls_needs_bypass_reapply = False
                await super().execute(
                    sqlalchemy.text("SET LOCAL rls.bypass_rls = true;")
                )
            # Always skip normal RLS context settings when bypassing.
            return
        set_statements = self._get_set_statements()
        for stmt in set_statements:
            await super().execute(stmt)
        if set_statements:
            self._mark_context_applied_to_current_transaction()

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
        if self._rls_bypass:
            self._rls_needs_bypass_reapply = True

    def bypass_rls(self) -> AsyncBypassRLSContext:
        return AsyncBypassRLSContext(self)
