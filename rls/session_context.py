"""Validation and rendering of the pydantic context used by RLS sessions.

The context's fields are sent to PostgreSQL with ``set_config`` and read back
by policy expressions through ``current_setting()``.  Everything here is
computed once per context class and cached.
"""

import datetime
import decimal
import enum
import functools
import types
import typing
import uuid
from collections import abc

import pydantic
import sqlalchemy

# Scalar types whose ``str()`` is a text representation PostgreSQL can cast
# back to the matching column type in a policy expression.  Enums are handled
# separately: they are rendered by their ``.value``.
SUPPORTED_SCALAR_TYPES: tuple[type, ...] = (
    str,
    int,
    float,
    bool,
    decimal.Decimal,
    uuid.UUID,
    datetime.datetime,
    datetime.date,
    datetime.time,
)

RenderValues = abc.Callable[[pydantic.BaseModel | None], dict[str, str]]

_ValueRenderer = abc.Callable[[object], str]

# ``type X = ...`` aliases (Python 3.12+).
_TYPE_ALIAS_TYPE: type | None = getattr(typing, "TypeAliasType", None)

BYPASS_STATEMENT = sqlalchemy.select(
    sqlalchemy.func.set_config(
        sqlalchemy.literal("rls.bypass_rls"),
        sqlalchemy.literal("true"),
        sqlalchemy.true(),
    )
)


def is_context_immutable(context: pydantic.BaseModel | None) -> bool:
    if context is None:
        return True
    model_config = getattr(type(context), "model_config", None)
    if model_config is None:
        return False
    return bool(model_config.get("frozen"))


# None is stored as an empty string, which policies turn back into NULL.
def _render_scalar(value: object) -> str:
    return "" if value is None else str(value)


def _render_enum(value: object) -> str:
    if isinstance(value, enum.Enum):
        value = value.value
    return _render_scalar(value)


def _unsupported_field_error(
    model: type[pydantic.BaseModel], key: str, annotation: object
) -> TypeError:
    return TypeError(
        f"Unsupported type {annotation!r} for RLS context field "
        f"{model.__name__}.{key}. Supported types are str, int, float, bool, "
        "Decimal, UUID, datetime, date, time, enums with str or int values, "
        "and Optional/Union combinations of these."
    )


def _annotation_types(annotation: object) -> list[object]:
    """Flattens an annotation into the list of types a field can hold.

    ``Optional``/``Union`` are expanded, and wrappers that do not change the
    runtime type (``Annotated``, ``NewType`` and ``type`` aliases) are
    unwrapped, including when nested inside an ``Optional``/``Union``: pydantic
    only strips a top-level ``Annotated`` from ``FieldInfo.annotation``, so
    e.g. ``Optional[PositiveInt]`` still contains one.
    """
    if _TYPE_ALIAS_TYPE is not None and isinstance(annotation, _TYPE_ALIAS_TYPE):
        return _annotation_types(annotation.__value__)  # type: ignore[attr-defined]
    if isinstance(annotation, typing.NewType):
        return _annotation_types(annotation.__supertype__)
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        return _annotation_types(typing.get_args(annotation)[0])
    if origin is typing.Union or origin is types.UnionType:
        return [
            leaf
            for arg in typing.get_args(annotation)
            for leaf in _annotation_types(arg)
        ]
    return [annotation]


def _is_supported_type(type_: object) -> bool:
    if not isinstance(type_, type):
        return False
    if issubclass(type_, enum.Enum):
        return all(isinstance(member.value, (str, int)) for member in type_)
    return issubclass(type_, SUPPORTED_SCALAR_TYPES)


def _value_renderer(
    model: type[pydantic.BaseModel], key: str, annotation: object
) -> _ValueRenderer:
    """Validates a context field's annotation and returns the function that
    renders its values as the text passed to ``set_config``."""
    # None (from Optional[...]) is always allowed and rendered as ''; every
    # other type the field can hold must be supported.  A field that can only
    # be None carries no information and is rejected.
    field_types = [
        type_
        for type_ in _annotation_types(annotation)
        if type_ is not None and type_ is not type(None)
    ]
    if not field_types or not all(_is_supported_type(type_) for type_ in field_types):
        raise _unsupported_field_error(model, key, annotation)
    if any(issubclass(type_, enum.Enum) for type_ in field_types):  # type: ignore[arg-type]
        return _render_enum
    return _render_scalar


@functools.cache
def render_values_function(model: type[pydantic.BaseModel]) -> RenderValues:
    """
    Pre-computes, at init time, the function that renders a context's field
    values into the bind parameters of the ``set_config`` statement template.

    Raises :class:`TypeError` if any field of ``model`` cannot be rendered to a
    value that RLS policy expressions can cast.
    """
    renderers = {
        f"value_{key}": (key, _value_renderer(model, key, field.annotation))
        for key, field in model.model_fields.items()
    }

    def render_values(context: pydantic.BaseModel | None) -> dict[str, str]:
        if context is None:
            return {}
        return {
            param: render(getattr(context, key))
            for param, (key, render) in renderers.items()
        }

    return render_values


def render_no_values(context: pydantic.BaseModel | None) -> dict[str, str]:
    return {}


@functools.cache
def set_statement_template(
    model: type[pydantic.BaseModel] | None,
) -> sqlalchemy.StatementLambdaElement:
    """
    Pre-computes, at init time, the SQL template for setting RLS config values
    for a context class (``None`` when the session has no context).

    All values are set transaction-locally (``is_local => true``), so they are
    discarded at the end of the transaction and never leak to other users of a
    pooled connection.

    The SQLAlchemy select() expression with literal setting names and named
    bind parameters for the values is built once and stored.  Each call to
    RlsSession._pending_rls_statements() then only needs to substitute the
    current field values into this template, which is significantly cheaper
    than rebuilding the entire statement every time.

    The template is wrapped in SQLAlchemy's lambda statement infrastructure so
    the statement construction and its compilation are cached; only the bound
    values need to be supplied at execution time.
    """
    keys = list(model.model_fields.keys()) if model is not None else []
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
    template = sqlalchemy.select(*set_config_calls)
    return sqlalchemy.lambda_stmt(lambda: template)
