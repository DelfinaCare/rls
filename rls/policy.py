import enum
import hashlib
import inspect
import re
import typing
from collections import abc

import pydantic
import sqlalchemy
from sqlalchemy import sql
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import elements

_CONDITION_ARGS_PREFIX = "rls"

# Used to quote identifiers (reserved words, mixed case, special characters)
# when building DDL statements.
_POSTGRES_DIALECT = postgresql.dialect()
_IDENTIFIER_PREPARER = _POSTGRES_DIALECT.identifier_preparer

# Postgres silently truncates identifiers longer than NAMEDATALEN - 1 bytes.
_MAX_IDENTIFIER_BYTES = 63
_POLICY_HASH_LENGTH = 8
# Lowercase, since Postgres folds unquoted identifiers to lowercase.
_POLICY_HASH_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

# Context field names are Python identifiers, so a comparator name that is not
# one can never be set by a session.
_COMPARATOR_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
BYPASS_RLS_SETTING = "bypass_rls"

# Role specifications that are keywords rather than role names, so they must
# not be quoted in ``TO`` clauses.
_ROLE_KEYWORDS = frozenset({"PUBLIC", "CURRENT_ROLE", "CURRENT_USER", "SESSION_USER"})


class Command(str, enum.Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class PolicyType(str, enum.Enum):
    permissive = "PERMISSIVE"
    restrictive = "RESTRICTIVE"


class RlsMode(str, enum.Enum):
    """How row level security is turned on for a table.

    ``enable`` only enables RLS, so the table owner bypasses the policies.
    ``enable_and_force`` also forces RLS, so the table owner is subject to them.
    """

    enable = "ENABLE"
    enable_and_force = "ENABLE_AND_FORCE"


DEFAULT_RLS_MODE = RlsMode.enable_and_force


def quote_identifier(name: str) -> str:
    """Quote a Postgres identifier if needed (e.g. reserved words, mixed case)."""
    return _IDENTIFIER_PREPARER.quote(name)


def quote_table(table_name: str, schemaname: str | None = None) -> str:
    """Return the quoted, optionally schema-qualified, name of a table."""
    quoted = quote_identifier(table_name)
    if schemaname is None:
        return quoted
    return f"{_IDENTIFIER_PREPARER.quote_schema(schemaname)}.{quoted}"


class ConditionArg(pydantic.BaseModel):
    """A context value referenced by a policy expression.

    ``type`` is the SQLAlchemy type the value is cast to in the policy.  It
    can be a type class (e.g. ``Integer``) or, when the type needs
    arguments, an instance (e.g. ``DateTime(timezone=True)`` for
    ``timestamptz`` or ``Enum(MyEnum, name="my_enum")`` for a native enum).
    """

    model_config = pydantic.ConfigDict(arbitrary_types_allowed=True)

    comparator_name: str
    type: type[sql.sqltypes.TypeEngine] | sql.sqltypes.TypeEngine

    @pydantic.field_validator("comparator_name")
    @classmethod
    def _check_comparator_name(cls, value: str) -> str:
        if not _COMPARATOR_NAME_PATTERN.fullmatch(value):
            raise ValueError(
                f"comparator_name {value!r} must be a valid Python identifier, "
                "since it has to match the name of a context field"
            )
        if value == BYPASS_RLS_SETTING:
            raise ValueError(f"comparator_name cannot be {BYPASS_RLS_SETTING!r}")
        return value


def _wrap_rls_value_setting(
    value_name: str,
    value_type: type[sql.sqltypes.TypeEngine] | sql.sqltypes.TypeEngine,
) -> elements.ColumnElement:
    return sql.func.nullif(
        sql.func.current_setting(f"{_CONDITION_ARGS_PREFIX}.{value_name}", True),
        "",
    ).cast(value_type)


def compile_sqla_expr(
    expr: typing.Callable[..., elements.ColumnElement],
    condition_args: list[ConditionArg] | None,
    allow_bypass_rls: bool = True,
) -> str:
    """Validate and compile a custom expression into a SQL string.

    Returns the compiled SQL expression string.
    """

    condition_args_length = len(condition_args) if condition_args is not None else 0
    lambda_args_length = len(inspect.signature(expr).parameters)
    if condition_args_length != lambda_args_length:
        raise ValueError(
            f"Length mismatch for arguments. Expected {condition_args_length}, got {lambda_args_length}"
        )

    args = []
    for arg in condition_args or []:
        args.append(_wrap_rls_value_setting(arg.comparator_name, arg.type))

    clause_element = expr(*args)

    if not isinstance(clause_element.type, sqlalchemy.Boolean):
        raise TypeError("Expression does not evaluate to a Boolean value")

    if allow_bypass_rls:
        clause_element = sql.or_(
            clause_element,
            _wrap_rls_value_setting(BYPASS_RLS_SETTING, sqlalchemy.Boolean) == True,
        )

    # Compile for PostgreSQL: the generic dialect renders some types with
    # names Postgres does not have or that do not round-trip the value (e.g.
    # DateTime as DATETIME, Uuid as CHAR(32)).
    return str(
        clause_element.compile(
            dialect=_POSTGRES_DIALECT, compile_kwargs={"literal_binds": True}
        )
    )


def render_role(role: str) -> str:
    """Render a role for a ``TO`` clause, quoting it unless it is a keyword
    such as ``PUBLIC`` or ``CURRENT_USER``."""
    if role.upper() in _ROLE_KEYWORDS:
        return role.upper()
    return quote_identifier(role)


def _hashed_policy_name(
    base_name: str,
    policy_type: PolicyType,
    cmd: Command,
    expr: str,
    check_expr: str | None = None,
    roles: abc.Sequence[str] | None = None,
) -> str:
    """Append a short hash of the policy definition to ``base_name``.

    Postgres rewrites policy expressions when storing them, so the stored
    expression cannot be reliably compared to the one generated by
    SQLAlchemy.  Embedding a hash of the policy type, command, expressions
    and roles in the policy name lets us detect changes by comparing names
    alone.  The check expression and roles are only hashed when set, so
    names of policies that do not use them are unchanged.

    The base name is truncated if needed so that the resulting identifier
    fits within Postgres' identifier length limit (otherwise Postgres would
    truncate the hash away).
    """
    policy_sql = f"{policy_type.value} {cmd.value} {expr}"
    if check_expr is not None:
        policy_sql += f" WITH CHECK {check_expr}"
    if roles is not None:
        policy_sql += f" TO {', '.join(render_role(role) for role in roles)}"
    value = int.from_bytes(hashlib.sha256(policy_sql.encode("utf-8")).digest())
    base_len = len(_POLICY_HASH_ALPHABET)
    chars = []
    for _ in range(_POLICY_HASH_LENGTH):
        value, rem = divmod(value, base_len)
        chars.append(_POLICY_HASH_ALPHABET[rem])
    digest = "".join(chars)
    max_base_bytes = _MAX_IDENTIFIER_BYTES - len(digest) - 1
    base = base_name.encode("utf-8")[:max_base_bytes].decode("utf-8", "ignore")
    return f"{base}_{digest}"


class Policy(pydantic.BaseModel):
    """A single row-level security policy attached to a database table.

    ``expr`` is the ``USING`` expression, except for ``INSERT`` policies where
    it is the ``WITH CHECK`` expression.  ``check_expr`` is an optional,
    separate ``WITH CHECK`` expression for ``UPDATE`` and ``ALL`` policies;
    when it is not set, Postgres checks new rows with ``expr``.

    ``roles`` lists the roles the policy applies to (``TO ...``); ``None``
    applies it to all roles (``PUBLIC``).

    ``comparator_names`` are the context fields the policy reads, used to
    validate the context model (see ``rls.register``).
    """

    cmd: Command = Command.all
    expr: str
    name: str
    policy_type: PolicyType = PolicyType.permissive
    check_expr: str | None = None
    roles: tuple[str, ...] | None = None
    comparator_names: tuple[str, ...] = ()

    @pydantic.model_validator(mode="after")
    def _check_policy(self) -> typing.Self:
        if self.check_expr is not None and self.cmd not in (
            Command.all,
            Command.update,
        ):
            raise ValueError(
                f"{self.cmd.value} policies cannot have a separate check_expr; "
                "only UPDATE and ALL policies have both USING and WITH CHECK"
            )
        if self.roles is not None and not self.roles:
            raise ValueError("roles must not be empty; use None for all roles")
        return self

    @classmethod
    def from_sqla(
        cls,
        expr: typing.Callable[..., elements.ColumnElement],
        condition_args: list[ConditionArg],
        cmd: Command,
        name: str | None = None,
        allow_bypass_rls: bool = True,
        policy_type: PolicyType = PolicyType.permissive,
        check_expr: typing.Callable[..., elements.ColumnElement] | None = None,
        roles: abc.Sequence[str] | None = None,
    ) -> "Policy":
        """Build a policy from a SQLAlchemy expression.

        ``check_expr`` is an optional ``WITH CHECK`` expression for ``UPDATE``
        and ``ALL`` policies.  It receives the same ``condition_args`` as
        ``expr``.

        The policy name ends with a short hash of the policy definition
        (type, command, compiled expressions and roles).  Postgres rewrites
        policy expressions when storing them, so alembic autogenerate detects
        changes by comparing policy names rather than expressions.
        """
        if isinstance(roles, str):
            raise TypeError("roles must be a sequence of role names, not a string")
        compiled_expr = compile_sqla_expr(expr, condition_args, allow_bypass_rls)
        compiled_check_expr = (
            compile_sqla_expr(check_expr, condition_args, allow_bypass_rls)
            if check_expr is not None
            else None
        )
        roles_tuple = tuple(roles) if roles is not None else None
        if name is None:
            name_parts: list[str] = [policy_type.value]
            name_parts.extend(arg.comparator_name for arg in condition_args)
            name_parts.append(cmd.value)
            name = "_".join(name_parts)
        hashed_name = _hashed_policy_name(
            name.lower(),
            policy_type,
            cmd,
            compiled_expr,
            check_expr=compiled_check_expr,
            roles=roles_tuple,
        )
        return cls(
            expr=compiled_expr,
            cmd=cmd,
            name=hashed_name,
            policy_type=policy_type,
            check_expr=compiled_check_expr,
            roles=roles_tuple,
            comparator_names=tuple(arg.comparator_name for arg in condition_args),
        )

    def render_policy(
        self, table_name: str, schemaname: str | None = None
    ) -> sqlalchemy.TextClause:
        """Generate a SQL CREATE POLICY statement.

        ``table_name`` and ``schemaname`` are unquoted identifiers; they, the
        policy name and the roles are quoted as needed.
        """

        # See docs here: https://www.postgresql.org/docs/current/sql-createpolicy.html
        header = (
            f"CREATE POLICY {quote_identifier(self.name)}"
            f" ON {quote_table(table_name, schemaname)}"
            f" AS {self.policy_type.value} FOR {self.cmd.value}"
        )
        if self.roles is not None:
            header += f" TO {', '.join(render_role(role) for role in self.roles)}"
        using: str | None
        check: str | None
        match self.cmd:
            case Command.select | Command.delete:
                using, check = self.expr, None
            case Command.insert:
                using, check = None, self.expr
            case Command.update:
                # Postgres would default WITH CHECK to USING; it is spelled
                # out to keep the generated DDL explicit.
                using, check = self.expr, self.check_expr or self.expr
            case Command.all:
                using, check = self.expr, self.check_expr
            case _:
                raise ValueError(f'Unknown policy command "{self.cmd}"')
        clauses = []
        if using is not None:
            clauses.append(f"USING ({using})")
        if check is not None:
            clauses.append(f"WITH CHECK ({check})")
        # Escape colons so that quoted identifiers are not parsed as bind params.
        header = header.replace(":", "\\:")
        return sqlalchemy.text(" ".join([header, *clauses]))


def check_unique_policy_names(
    table_name: str, policies: abc.Iterable["Policy | ExternalPolicy"]
) -> None:
    """Raise ``ValueError`` if two policies on a table share a name.

    Policy names embed a hash of the definition, so two identical policies
    with the same base name get the same name, which Postgres rejects.
    """
    seen: set[str] = set()
    duplicates: set[str] = set()
    for p in policies:
        if p.name in seen:
            duplicates.add(p.name)
        seen.add(p.name)
    if duplicates:
        raise ValueError(
            f"Duplicate RLS policy names on table {table_name!r}: "
            f"{sorted(duplicates)}. Remove the duplicate policies or give "
            "them different names."
        )


class ExternalPolicy(pydantic.BaseModel):
    """A row-level security policy managed outside of this package.

    List an ``ExternalPolicy`` in a model's ``__rls_policies__`` to declare
    that a policy with this name already exists on the table and is managed
    elsewhere (e.g. by hand-written migrations).  Alembic autogenerate will
    neither create nor drop it, and
    ``rls.create_policies.create_policies_no_commit`` skips it.  This allows
    an existing RLS codebase to be migrated to this package one policy at a
    time.

    ``name`` must match the policy name stored in Postgres exactly.
    """

    name: str
