import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio


class _RlsSessionMixin:
    """Shared logic for RlsSession and AsyncRlsSession."""

    def __init__(self, context: pydantic.BaseModel | None = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rls_bypass_depth = 0  # Track RLS bypass nesting depth
        self._rls_set_template: sqlalchemy.Select | None = None
        self._rls_context_keys: list[str] = []
        if context is not None:
            self.context = context
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

        # Only value substitution happens here — the template with literal setting
        # names was already built during _precompute_set_template().
        value_params = {}
        for key in self._rls_context_keys:
            val = getattr(self.context, key)
            value_params[f"value_{key}"] = "" if val is None else str(val)
        return [self._rls_set_template.params(**value_params)]


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
                self.session.rollback()
            return
        if self._is_outermost:
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
                await self.session.rollback()
            return
        if self._is_outermost:
            await self.session.execute(
                sqlalchemy.text("SET LOCAL rls.bypass_rls = false;")
            )


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
