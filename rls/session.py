import typing
from collections import abc

import pydantic
import sqlalchemy
from sqlalchemy import event
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


_BYPASS_STATEMENT = sqlalchemy.select(
    sqlalchemy.func.set_config(
        sqlalchemy.literal("rls.bypass_rls"),
        sqlalchemy.literal("true"),
        sqlalchemy.true(),
    )
)


def _set_statement_template(keys: list[str]) -> sqlalchemy.Select:
    """
    Pre-computes the SQL template for setting RLS config values at init time.

    All values are set transaction-locally (``is_local => true``), so they are
    discarded at the end of the transaction and never leak to other users of a
    pooled connection.

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
            sqlalchemy.true(),
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
                sqlalchemy.true(),
            )
        )
    return sqlalchemy.select(*set_config_calls)


class _RlsSessionState:
    """Tracks which RLS settings have been applied for an :class:`RlsSession`.

    Settings are applied with ``set_config(..., is_local => true)`` so they
    only last until the end of the current transaction and can never leak to
    the next user of a pooled connection.

    ``_rls_dirty`` records that the desired settings may differ from what was
    last sent to the database (bypass was entered or exited, or a transaction
    or savepoint ended).  Together with the context snapshot it lets us skip
    the ``set_config`` round trip on every statement where nothing changed.
    """

    def __init__(self, context: pydantic.BaseModel | None) -> None:
        self._rls_bypass_depth = 0  # Track RLS bypass nesting depth
        self._rls_dirty = True
        self._rls_last_set_context_snapshot: pydantic.BaseModel | None = None
        # Connections participating in the current root transaction.
        self._rls_connections: list[sqlalchemy.Connection] = []
        self._context = context
        self._rls_context_is_immutable = _is_context_immutable(context)
        self._rls_context_keys: list[str] = (
            list(type(self._context).model_fields.keys()) if self._context else []
        )
        template = _set_statement_template(self._rls_context_keys)
        # Wrap the template in SQLAlchemy's lambda statement infrastructure so
        # the statement construction and its compilation are cached; only the
        # bound values need to be supplied at execution time.
        self._rls_set_statement = sqlalchemy.lambda_stmt(lambda: template)

    def _rls_needs_apply(self) -> bool:
        if self._rls_dirty:
            return True
        if self._rls_bypass_depth > 0 or self._rls_context_is_immutable:
            return False
        return self._context != self._rls_last_set_context_snapshot

    def _get_set_statement(
        self,
    ) -> tuple[sqlalchemy.Executable, dict[str, str]]:
        """
        Returns the SQL statement to set all RLS config values, along with the
        bound parameter values to execute it with.

        The statement was pre-compiled into a SQLAlchemy lambda statement at
        init time; here we only compute the current field values.  None values
        are stored as an empty string so that the RLS policy expressions (which
        wrap current_setting() with NULLIF(..., '')) treat them as NULL and
        filter out all rows.
        """
        if self._rls_bypass_depth > 0:
            return _BYPASS_STATEMENT, {}
        self._rls_last_set_context_snapshot = (
            self._context.model_copy(deep=True) if self._context else None
        )
        return self._rls_set_statement, _context_to_value_params(
            self._rls_last_set_context_snapshot, self._rls_context_keys
        )

    def _rls_sync(self, new_connection: sqlalchemy.Connection | None = None) -> None:
        """Apply RLS settings to the connections of the current transaction.

        A newly begun connection always receives the settings; existing
        connections only receive them if the desired state has changed.
        """
        needs_apply = self._rls_needs_apply()
        if new_connection is not None:
            self._rls_connections.append(new_connection)
        if needs_apply:
            targets = self._rls_connections
        elif new_connection is not None:
            targets = [new_connection]
        else:
            return
        if targets:
            statement, params = self._get_set_statement()
            for connection in targets:
                connection.execute(statement, params)
        self._rls_dirty = False

    def _rls_transaction_ended(self, transaction: orm.SessionTransaction) -> None:
        if transaction.parent is None:
            # Transaction-local settings are gone with the transaction.
            self._rls_connections = []
            self._rls_dirty = True
        elif transaction.nested:
            # Rolling back to a savepoint reverts settings made inside it.
            self._rls_dirty = True


class RlsSessionTransaction:
    """Wraps :class:`~sqlalchemy.orm.SessionTransaction` so that every
    commit / rollback marks the owning :class:`RlsSession` as *dirty*,
    ensuring RLS configuration is re-applied on the next statement.
    """

    # Composition is used instead of inheritance because ``SessionTransaction``
    # is instantiated internally by ``Session.begin()`` with private state
    # (``SessionTransactionOrigin``, parent chain, snapshot).  We need to wrap
    # the already-constructed instance rather than create a new subclass
    # instance, so delegation is the only viable approach.

    def __init__(
        self,
        transaction: orm.SessionTransaction,
        session: "RlsSession",
    ) -> None:
        self._transaction = transaction
        self._session = session

    def __enter__(self) -> typing.Self:
        self._transaction.__enter__()
        self._session._rls_dirty = True
        return self

    def __exit__(self, type_: object, value: object, traceback: object) -> None:
        try:
            self._transaction.__exit__(type_, value, traceback)
        finally:
            self._session._rls_dirty = True

    def commit(self) -> None:
        self._transaction.commit()
        self._session._rls_dirty = True

    def rollback(self) -> None:
        self._transaction.rollback()
        self._session._rls_dirty = True

    def close(self, invalidate: bool = False) -> None:
        self._transaction.close(invalidate=invalidate)

    def prepare(self) -> None:
        self._transaction.prepare()

    @property
    def session(self) -> "RlsSession":
        return self._session

    @property
    def is_active(self) -> bool:
        return self._transaction.is_active  # type: ignore[return-value]

    @property
    def parent(self) -> orm.SessionTransaction | None:
        return self._transaction.parent

    @property
    def nested(self) -> bool:
        return self._transaction.nested  # type: ignore[return-value]


class RlsAsyncSessionTransaction:
    """Wraps :class:`~sqlalchemy.ext.asyncio.AsyncSessionTransaction` so that
    every commit / rollback marks the owning :class:`AsyncRlsSession` as
    *dirty*, ensuring RLS configuration is re-applied on the next statement.
    """

    # Composition is used instead of inheritance because
    # ``AsyncSessionTransaction`` is instantiated internally by
    # ``AsyncSession.begin()`` with private state.  We need to wrap the
    # already-constructed instance rather than create a new subclass instance,
    # so delegation is the only viable approach.

    # Differences from :class:`RlsSessionTransaction` that are required by the
    # underlying ``AsyncSessionTransaction`` API:

    # * ``close()`` is absent — ``AsyncSessionTransaction`` has no ``close()``
    #   method (unlike the sync ``SessionTransaction``).
    # * ``parent`` is absent — ``AsyncSessionTransaction`` has no ``parent``
    #   property (unlike the sync ``SessionTransaction``).
    # * ``start()`` / ``__await__`` are present — ``AsyncSessionTransaction``
    #   uses an explicit async-start pattern rather than ``__enter__``, allowing
    #   the object to be both awaited directly and used as an async context
    #   manager (see ``start`` and ``__await__`` below).
    # * ``sync_transaction`` is present — async-only property that exposes the
    #   underlying sync ``SessionTransaction`` (no equivalent exists in the sync
    #   wrapper).

    def __init__(
        self,
        transaction: sa_asyncio.AsyncSessionTransaction,
        session: "AsyncRlsSession",
    ) -> None:
        self._transaction = transaction
        self._session = session

    async def start(self, is_ctxmanager: bool = False) -> typing.Self:
        # Unlike the sync SessionTransaction which begins implicitly via
        # __enter__, AsyncSessionTransaction exposes an explicit start() method.
        # The is_ctxmanager flag tells SQLAlchemy whether the transaction was
        # entered through an async context manager (True) or awaited directly
        # (False), allowing both usage patterns:
        #   async with session.begin() as tx: ...   # context-manager usage
        #   tx = await session.begin()              # direct-await usage
        await self._transaction.start(is_ctxmanager=is_ctxmanager)
        self._session._rls_dirty = True
        return self

    def __await__(
        self,
    ) -> abc.Generator[object, object, "RlsAsyncSessionTransaction"]:
        # AsyncSessionTransaction (unlike the sync SessionTransaction) supports
        # being awaited directly in addition to being used as an async context
        # manager.  This makes ``tx = await session.begin()`` possible.
        return self.start().__await__()

    async def __aenter__(self) -> typing.Self:
        return await self.start(is_ctxmanager=True)

    async def __aexit__(self, type_: object, value: object, traceback: object) -> None:
        try:
            await self._transaction.__aexit__(type_, value, traceback)
        finally:
            self._session._rls_dirty = True

    async def commit(self) -> None:
        await self._transaction.commit()
        self._session._rls_dirty = True

    async def rollback(self) -> None:
        await self._transaction.rollback()
        self._session._rls_dirty = True

    async def prepare(self) -> None:
        # AsyncSessionTransaction has no prepare() method (unlike the sync
        # SessionTransaction).  AsyncRlsSession.prepare() is called instead,
        # which uses run_sync() to invoke the underlying sync Session.prepare().
        await self._session.prepare()

    @property
    def session(self) -> "AsyncRlsSession":
        return self._session

    @property
    def is_active(self) -> bool:
        return self._transaction.is_active  # type: ignore[return-value]

    @property
    def nested(self) -> bool:
        return self._transaction.nested  # type: ignore[return-value]

    @property
    def sync_transaction(self) -> orm.SessionTransaction | None:
        # Async-only property: exposes the underlying sync SessionTransaction
        # that AsyncSessionTransaction wraps.  There is no equivalent in the
        # sync RlsSessionTransaction because SessionTransaction is itself the
        # "sync transaction" and wraps no further layer.
        return self._transaction.sync_transaction


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
        if self.session._rls_bypass_depth == 0:
            self.session._rls_dirty = True


class AsyncBypassRLSContext:
    def __init__(self, session: "AsyncRlsSession"):
        self.session = session

    async def __aenter__(self):
        BypassRLSContext(self.session.sync_session).__enter__()
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        BypassRLSContext(self.session.sync_session).__exit__(exc_type, exc_val, exc_tb)


class RlsSession(_RlsSessionState, orm.Session):
    """A :class:`~sqlalchemy.orm.Session` that applies RLS settings.

    Settings are applied through session events, so every way the session
    talks to the database (``execute``, ``get``, lazy loads, ``refresh``,
    flushes and ``connection()``) runs with the session's context.
    """

    def __init__(self, context: pydantic.BaseModel | None = None, *args, **kwargs):
        _RlsSessionState.__init__(self, context)
        orm.Session.__init__(self, *args, **kwargs)

    def begin(self, nested: bool = False) -> "RlsSessionTransaction":  # type: ignore[override]
        return RlsSessionTransaction(super().begin(nested=nested), self)

    def connection(self, *args, **kwargs) -> sqlalchemy.Connection:
        connection = super().connection(*args, **kwargs)
        self._rls_sync()
        return connection

    def commit(self):
        super().commit()
        self._rls_dirty = True

    def rollback(self):
        super().rollback()
        self._rls_dirty = True

    def bypass_rls(self) -> BypassRLSContext:
        return BypassRLSContext(self)


@event.listens_for(RlsSession, "after_begin")
def _rls_after_begin(
    session: orm.Session,
    transaction: orm.SessionTransaction,
    connection: sqlalchemy.Connection,
) -> None:
    if isinstance(session, RlsSession) and connection not in session._rls_connections:
        session._rls_sync(new_connection=connection)


@event.listens_for(RlsSession, "do_orm_execute")
def _rls_do_orm_execute(orm_execute_state: orm.ORMExecuteState) -> None:
    session = orm_execute_state.session
    if isinstance(session, RlsSession):
        session._rls_sync()


@event.listens_for(RlsSession, "before_flush")
def _rls_before_flush(
    session: orm.Session, flush_context: orm.UOWTransaction, instances: object
) -> None:
    if isinstance(session, RlsSession):
        session._rls_sync()


@event.listens_for(RlsSession, "after_transaction_end")
def _rls_after_transaction_end(
    session: orm.Session, transaction: orm.SessionTransaction
) -> None:
    if isinstance(session, RlsSession):
        session._rls_transaction_ended(transaction)


class AsyncRlsSession(sa_asyncio.AsyncSession):
    """An :class:`~sqlalchemy.ext.asyncio.AsyncSession` that applies RLS settings.

    All work is delegated to an underlying :class:`RlsSession`, so RLS is also
    applied to operations that :class:`~sqlalchemy.ext.asyncio.AsyncSession`
    runs on its sync session (``get``, ``refresh``, ``stream``, lazy loads,
    flushes, ...).
    """

    sync_session_class: type[orm.Session] = RlsSession
    sync_session: RlsSession

    def __init__(self, context: pydantic.BaseModel | None = None, *args, **kwargs):
        sync_session_class = kwargs.get("sync_session_class") or self.sync_session_class
        if not issubclass(sync_session_class, RlsSession):
            raise TypeError(
                f"sync_session_class {sync_session_class.__name__} must be RlsSession or a subclass of RlsSession"
            )
        super().__init__(*args, context=context, **kwargs)

    @property
    def _context(self) -> pydantic.BaseModel | None:
        return self.sync_session._context

    @property
    def _rls_bypass_depth(self) -> int:
        return self.sync_session._rls_bypass_depth

    @property
    def _rls_dirty(self) -> bool:
        return self.sync_session._rls_dirty

    @_rls_dirty.setter
    def _rls_dirty(self, value: bool) -> None:
        self.sync_session._rls_dirty = value

    def begin(self) -> RlsAsyncSessionTransaction:  # type: ignore[override]
        # AsyncSession.begin() does not accept a nested parameter (unlike
        # sync Session.begin(nested=False)).  To create nested transactions
        # (savepoints) in async code, use begin_nested() instead.
        return RlsAsyncSessionTransaction(super().begin(), self)

    async def prepare(self) -> None:
        # AsyncSession has no prepare() method (unlike sync Session, which
        # exposes Session.prepare() directly).  This override is required so
        # that RlsAsyncSessionTransaction.prepare() has a target to call; it
        # uses run_sync() to invoke the underlying sync Session.prepare().
        await self.run_sync(lambda sess: sess.prepare())

    def bypass_rls(self) -> AsyncBypassRLSContext:
        return AsyncBypassRLSContext(self)
