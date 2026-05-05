from sqlalchemy import orm

from rls import alembic_ops


def register_alembic(Base: type[orm.DeclarativeMeta]):
    """Register ``Base`` with the RLS alembic integration.

    Call this in your application setup so that Alembic autogenerate has policy
    metadata available immediately.  This is the recommended way to wire up a
    declarative base for use with the RLS alembic operations.
    """
    alembic_ops.set_metadata_info(Base)
    return Base
