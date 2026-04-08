import abc
from typing import Any, Optional

import fastapi
import pydantic
from sqlalchemy import orm

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

    def __call__(
        self, *args: Optional[Any], **kwargs: Optional[Any]
    ):  # Get context from the context getter
        context = self.context_getter.get_context(*args, **kwargs)
        session = self.session_maker(context=context)
        try:
            return session
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()


# For Fastapi


def fastapi_dependency_function(RlsSessioner: RlsSessioner):
    def dependency_function(request: fastapi.Request):
        return RlsSessioner(request=request)

    return dependency_function
