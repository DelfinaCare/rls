import typing
from collections import abc

import pydantic
import sqlalchemy
from sqlalchemy import event
from sqlalchemy import orm

from rls import policy

_CONTEXT_MODEL_KEY = "rls_context_model"


def _check_context_fields(
    table_name: str,
    policies: abc.Iterable[
        policy.Policy | policy.ExternalPolicy | policy.RelationshipPolicy
    ],
    context_model: type[pydantic.BaseModel],
) -> None:
    """Raise ``ValueError`` if a policy reads a field the context lacks.

    Policies read context values with ``current_setting(..., true)``, which
    returns NULL for unset settings, so a misspelled ``comparator_name``
    would otherwise silently hide every row.
    """
    fields = set(context_model.model_fields)
    for p in policies:
        if isinstance(p, policy.ExternalPolicy):
            continue
        missing = [name for name in p.comparator_names if name not in fields]
        if missing:
            label = (
                f"for relationship {p.relationship!r}"
                if isinstance(p, policy.RelationshipPolicy)
                else repr(p.name)
            )
            raise ValueError(
                f"RLS policy {label} on table {table_name!r} reads "
                f"{missing}, which are not fields of "
                f"{context_model.__name__} (fields: {sorted(fields)})"
            )


def validate_context(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
    context_model: type[pydantic.BaseModel],
) -> None:
    """Check that ``context_model`` has every field read by ``Base``'s policies.

    Raises ``ValueError`` naming the first policy whose ``ConditionArg``
    ``comparator_name`` is not a field of ``context_model``.  ``Base`` must
    have been registered with ``base_wrapper``.
    """
    if "rls_policies" not in Base.metadata.info:
        raise ValueError(
            f"{Base.__name__} is not registered for RLS; call "
            "rls.register.base_wrapper(Base) first."
        )
    for table_name, policies in Base.metadata.info["rls_policies"].items():
        _check_context_fields(table_name, policies, context_model)


def table_policies(
    table: sqlalchemy.Table,
    policies: abc.Sequence[policy.Policy | policy.ExternalPolicy],
    rls_mode: policy.RlsMode | str = policy.DEFAULT_RLS_MODE,
) -> None:
    """Declare the RLS policies of a table that has no mapped class, such as
    the association (``secondary``) table of a many-to-many relationship.

    This is the equivalent of ``__rls_policies__`` and ``__rls_mode__`` on a
    model.  The table's metadata must have been registered with
    ``base_wrapper``.  Raises ``ValueError`` if the table already has
    policies, if two policies share a name, or if a context model was
    registered and a policy reads a field it lacks.
    """
    info = table.metadata.info
    if "rls_policies" not in info:
        raise ValueError(
            f"The metadata of table {table.fullname!r} is not registered for "
            "RLS; call rls.register.base_wrapper(Base) first."
        )
    policies = list(policies)
    for p in policies:
        if not isinstance(p, policy.Policy | policy.ExternalPolicy):
            raise TypeError(
                f"Policies of table {table.fullname!r} must be Policy or "
                f"ExternalPolicy objects, not {type(p).__name__}. "
                "Policy.from_relationship needs a mapped class."
            )
    if info["rls_policies"].get(table.fullname):
        raise ValueError(f"Table {table.fullname!r} already has RLS policies.")
    policy.check_unique_policy_names(table.fullname, policies)
    context_model = info.get(_CONTEXT_MODEL_KEY)
    if context_model is not None:
        _check_context_fields(table.fullname, policies, context_model)
    mode = policy.RlsMode(rls_mode)
    info["rls_policies"][table.fullname] = policies
    info.setdefault("rls_modes", {})[table.fullname] = mode


def base_wrapper(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
    context_model: type[pydantic.BaseModel] | None = None,
) -> type[orm.DeclarativeMeta] | type[orm.DeclarativeBase]:
    """Register ``Base`` with the RLS alembic integration.

    Call this in your application setup so that Alembic autogenerate has policy
    metadata available immediately.  This is the recommended way to wire up a
    declarative base for use with the RLS alembic operations.

    If you are not using Alembic, you can also create policies by calling
    rls.create_policies.create_policies_no_commit directly (in your own
    transaction, since it does not commit).

    If ``context_model`` (the pydantic model used as the session context) is
    given, the policies of every model, including ones mapped later, are
    checked to only read fields of it; see ``validate_context``.
    """
    # Register the alembic operations
    from rls import alembic_ops as _  # noqa: F401

    Base.metadata.info.setdefault("rls_policies", {})
    Base.metadata.info.setdefault("rls_modes", {})
    if context_model is not None:
        Base.metadata.info[_CONTEXT_MODEL_KEY] = context_model
    # Call the hook for already mapped classes.
    for mapper in Base.registry.mappers:
        base_wrapper_hook(mapper, mapper.class_)
    return Base


@event.listens_for(orm.Mapper, "after_mapper_constructed")
def base_wrapper_hook(mapper: orm.Mapper, class_: orm.DeclarativeMeta) -> None:
    """Listen for mappers being configured, and add any __rls_policies__ (and
    the optional __rls_mode__) to the metadata info dict which has an
    rls_policies key.

    Raises ``ValueError`` if two policies on the table share a name, or if a
    context model was registered and a policy reads a field it lacks.

    Policies are registered against the mapper's own (local) table.  A
    subclass that merely inherits ``__rls_policies__`` from a mapped parent
    does not register anything, so the parent's policies are left intact.
    Single-table inheritance subclasses share their parent's table, so they
    may not declare their own policies.
    """
    if "rls_policies" not in class_.metadata.info:
        return
    rls_policies = getattr(class_, "__rls_policies__", None)
    if rls_policies is None:
        return
    if mapper.inherits is not None and rls_policies is getattr(
        mapper.inherits.class_, "__rls_policies__", None
    ):
        # Inherited from a mapped parent, which registers them itself.
        return
    if mapper.single:
        raise TypeError(
            f"{class_.__name__} uses single-table inheritance and shares the "
            f"{mapper.local_table.description!r} table with its parent, so it "
            "cannot declare its own __rls_policies__. Declare them on the "
            "class that defines the table instead."
        )
    table_name = typing.cast(sqlalchemy.Table, mapper.local_table).fullname
    policy.check_unique_policy_names(table_name, rls_policies)
    context_model = class_.metadata.info.get(_CONTEXT_MODEL_KEY)
    if context_model is not None:
        _check_context_fields(table_name, rls_policies, context_model)
    class_.metadata.info["rls_policies"][table_name] = rls_policies
    # Policies derived from relationships can only be built once the mappers
    # are configured; policy.resolved_policies does that when they are used.
    pending = class_.metadata.info.setdefault(policy.RELATIONSHIP_MAPPERS_KEY, {})
    if any(isinstance(p, policy.RelationshipPolicy) for p in rls_policies):
        pending[table_name] = mapper
    else:
        pending.pop(table_name, None)
    class_.metadata.info.setdefault("rls_modes", {})[table_name] = policy.RlsMode(
        getattr(class_, "__rls_mode__", policy.DEFAULT_RLS_MODE)
    )
