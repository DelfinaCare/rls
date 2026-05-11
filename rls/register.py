from sqlalchemy import event
from sqlalchemy import orm


def base_wrapper(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
) -> type[orm.DeclarativeMeta] | type[orm.DeclarativeBase]:
    """Register ``Base`` with the RLS alembic integration.

    Call this in your application setup so that Alembic autogenerate has policy
    metadata available immediately.  This is the recommended way to wire up a
    declarative base for use with the RLS alembic operations.

    If you are not using Alembic, you can also create policies by calling
    rls.create_policies directly.
    """
    # Register the alembic operations
    from rls import alembic_ops as _  # noqa: F401

    Base.metadata.info.setdefault("rls_policies", dict())
    # Call the hook for already mapped classes.
    for mapper in Base.registry.mappers:
        base_wrapper_hook(mapper, mapper.class_)
    return Base


@event.listens_for(orm.Mapper, "after_mapper_constructed")
def base_wrapper_hook(mapper: orm.Mapper, class_: orm.DeclarativeMeta) -> None:
    """Listen for mappers being configured, and add any __rls_policies__ to the
    metadata info dict which has an rls_policies key.
    """
    if "rls_policies" not in class_.metadata.info:
        return
    if not hasattr(class_, "__rls_policies__"):
        return
    class_.metadata.info["rls_policies"][mapper.tables[0].fullname] = (
        class_.__rls_policies__
    )
