from typing import Type

from sqlalchemy import event
from sqlalchemy.ext.declarative import DeclarativeMeta

from rls.alembic_rls import set_metadata_info

from .create_policies import create_policies


def register_rls(Base: Type[DeclarativeMeta]):
    # required for `alembic revision --autogenerate``
    set_metadata_info(Base)

    @event.listens_for(Base.metadata, "after_create")
    def receive_after_create(target, connection, tables, **kw):
        # required for `Base.metadata.create_all()`
        set_metadata_info(Base)
        create_policies(Base, connection)

    return Base
