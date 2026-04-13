import abc
import contextlib
import typing

import fastapi
import pydantic
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import rls_session


class ContextGetter(abc.ABC):
    @abc.abstractmethod
    def get_context(self, *args, **kwargs) -> pydantic.BaseModel:
        """Abstract method to get context"""
        pass


class RlsSessioner:
    def __init__(self, sessionmaker: orm.sessionmaker, context_getter: ContextGetter):
        if not issubclass(sessionmaker.class_, rls_session.RlsSession):
            raise ValueError(
                "sessionmaker class must be RlsSession or a subclass of RlsSession"
            )

        self.session_maker: orm.sessionmaker[rls_session.RlsSession] = sessionmaker
        self.context_getter: ContextGetter = context_getter

    @contextlib.contextmanager
    def __call__(self, *args: typing.Any, **kwargs: typing.Any):
        context = self.context_getter.get_context(*args, **kwargs)
        session = self.session_maker(context=context)
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


class AsyncRlsSessioner:
    def __init__(
        self,
        sessionmaker: sa_asyncio.async_sessionmaker,
        context_getter: ContextGetter,
    ):
        if not issubclass(sessionmaker.class_, rls_session.AsyncRlsSession):
            raise ValueError(
                "sessionmaker class must be AsyncRlsSession or a subclass of AsyncRlsSession"
            )

        self.session_maker: sa_asyncio.async_sessionmaker[
            rls_session.AsyncRlsSession
        ] = sessionmaker
        self.context_getter: ContextGetter = context_getter

    @contextlib.asynccontextmanager
    async def __call__(self, *args: typing.Any, **kwargs: typing.Any):
        context = self.context_getter.get_context(*args, **kwargs)
        session = self.session_maker(context=context)
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# For Fastapi


def fastapi_dependency_function(sessioner: RlsSessioner):
    def dependency_function(request: fastapi.Request):
        with sessioner(request=request) as session:
            yield session

    return dependency_function
