import sqlalchemy
from sqlalchemy.ext import declarative

from rls import alembic_rls

from . import create_policies


def register_rls(Base: type[declarative.DeclarativeMeta]):
    # Called here so that Alembic autogenerate has policy metadata available
    # immediately (before any DDL runs or the after_create event fires).
    alembic_rls.set_metadata_info(Base)

    @sqlalchemy.event.listens_for(Base.metadata, "after_create")
    def receive_after_create(target, connection, tables, **kw):
        # Called again here to pick up any models registered after register_rls()
        # was first invoked (e.g. models imported later), then apply the policies.
        alembic_rls.set_metadata_info(Base)
        create_policies.create_policies(Base, connection)

    return Base
