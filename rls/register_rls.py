from typing import Type

import sqlalchemy
from sqlalchemy.ext import declarative

from rls import alembic_rls

from . import create_policies


def register_rls(Base: Type[declarative.DeclarativeMeta]):
    # required for `alembic revision --autogenerate``
    alembic_rls.set_metadata_info(Base)

    @sqlalchemy.event.listens_for(Base.metadata, "after_create")
    def receive_after_create(target, connection, tables, **kw):
        # required for `Base.metadata.create_all()`
        alembic_rls.set_metadata_info(Base)
        create_policies.create_policies(Base, connection)

    return Base
