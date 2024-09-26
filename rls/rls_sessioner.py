import abc
from sqlalchemy.orm import sessionmaker as SessionMaker
from rls.rls_session import RlsSession
from pydantic import BaseModel
from typing import Any, Optional
from fastapi import Request


class ContextGetter(abc.ABC):
    @abc.abstractmethod
    def get_context(self, *args, **kwargs) -> BaseModel:
        """Abstract method to get context"""
        pass


class RlsSessioner:
    def __init__(self, sessionmaker: SessionMaker, context_getter: ContextGetter):
        if not issubclass(sessionmaker.class_, RlsSession):
            raise ValueError(
                "sessionmaker class must be RlsSession or a subclass of RlsSession"
            )

        self.session_maker: SessionMaker[RlsSession] = sessionmaker
        self.context_getter: ContextGetter = context_getter

    def __call__(
        self, *args: Optional[Any], **kwargs: Optional[Any]
    ):  # Get context from the context getter
        print("Kwargs:", kwargs)
        print("Args:", args)
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
    def dependency_function(request: Request):
        return RlsSessioner(request=request)

    return dependency_function
