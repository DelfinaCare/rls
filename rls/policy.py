import enum
import hashlib
import inspect
import re
import typing
from collections import abc

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy import sql
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import interfaces as orm_interfaces
from sqlalchemy.sql import elements
from sqlalchemy.sql import operators
from sqlalchemy.sql import util as sql_util
from sqlalchemy.sql import visitors

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

# ``MetaData.info`` keys.  ``rls_policies`` maps table names to the policies
# declared for them; ``RELATIONSHIP_MAPPERS_KEY`` maps the tables that still
# have unresolved ``RelationshipPolicy`` entries to their mapper.
_POLICIES_KEY = "rls_policies"
RELATIONSHIP_MAPPERS_KEY = "rls_relationship_mappers"


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
        policy_sql += f" TO {', '.join(render_role(role) for role in sorted(roles))}"
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

    @classmethod
    def from_relationship(
        cls,
        relationship: str,
        cmd: Command = Command.all,
        condition_arg: ConditionArg | None = None,
        name: str | None = None,
        allow_bypass_rls: bool = True,
        policy_type: PolicyType = PolicyType.permissive,
        roles: abc.Sequence[str] | None = None,
    ) -> "RelationshipPolicy":
        """Declare a policy derived from one of the model's relationships.

        ``relationship`` is the name of a ``sqlalchemy.orm.relationship``
        attribute of the model the policy is declared on.

        Without ``condition_arg``, a row is accessible when it is related to
        at least one row the session can see: the policy checks that a
        related row ``EXISTS``, and Postgres applies the related table's own
        ``SELECT`` policies to that check.  A ``Book`` with an ``author``
        relationship is then accessible exactly when its ``Author`` is.

        With ``condition_arg``, a row is accessible when it is related to the
        row whose primary key is that context value.  For a many-to-one
        relationship this is a plain comparison of the foreign key column
        (``author_id = <context value>``); for a many-to-many relationship it
        looks the value up in the association table.

        Only a many-to-one relationship is stored on the row itself.  For
        the others, a new row has no links yet, so it never passes the
        policy's ``INSERT`` check: such rows can only be inserted with
        ``bypass_rls()``, or by sessions allowed by another ``INSERT``
        policy on the table.

        The links of a many-to-many relationship decide who can access a
        row, so its association table must have policies of its own (see
        ``rls.register.table_policies``).

        The expression is built from the relationship's join condition once
        the mappers are configured, so the returned ``RelationshipPolicy`` is
        only usable inside ``__rls_policies__``.  The remaining arguments
        behave as in ``from_sqla``; ``name`` defaults to
        ``<policy_type>_<relationship>_<comparator name>_<cmd>``.
        """
        if isinstance(roles, str):
            raise TypeError("roles must be a sequence of role names, not a string")
        return RelationshipPolicy(
            relationship=relationship,
            cmd=cmd,
            condition_arg=condition_arg,
            base_name=name,
            allow_bypass_rls=allow_bypass_rls,
            policy_type=policy_type,
            roles=tuple(roles) if roles is not None else None,
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
    table_name: str,
    policies: abc.Iterable["Policy | ExternalPolicy | RelationshipPolicy"],
) -> None:
    """Raise ``ValueError`` if two policies on a table share a name.

    Policy names embed a hash of the definition, so two identical policies
    with the same base name get the same name, which Postgres rejects.
    Relationship policies have no name until they are resolved, so
    unresolved ones are skipped.
    """
    seen: set[str] = set()
    duplicates: set[str] = set()
    for p in policies:
        if isinstance(p, RelationshipPolicy):
            continue
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


def _table_label(table: sql.FromClause) -> str:
    return getattr(table, "fullname", None) or str(table)


def _policy_table_column(column: sqlalchemy.Column) -> elements.ColumnElement:
    """Reference a column of the table the policy is attached to.

    A regular column would add its table to the ``FROM`` clause of the
    policy's subquery instead of referring to the row being checked.
    """
    table = typing.cast(sqlalchemy.Table, column.table)
    return sql.literal_column(
        f"{quote_table(table.name, table.schema)}.{quote_identifier(column.name)}",
        type_=column.type,
    )


def _is_column_equality(
    expr: elements.ColumnElement,
    a: elements.ColumnElement,
    b: elements.ColumnElement,
) -> bool:
    """Whether ``expr`` is exactly ``a = b`` (in either order), with no
    other criteria."""
    if not isinstance(expr, elements.BinaryExpression):
        return False
    if expr.operator is not operators.eq:
        return False
    left, right = expr.left, expr.right
    return (left.compare(a) and right.compare(b)) or (
        left.compare(b) and right.compare(a)
    )


class RelationshipPolicy(pydantic.BaseModel):
    """A policy derived from a relationship, see ``Policy.from_relationship``.

    The policy expression depends on the relationship's join condition, which
    is only known once SQLAlchemy has configured the mappers, so this is a
    declaration that is turned into a ``Policy`` by ``resolve`` (done for
    you by alembic autogenerate and ``create_policies_no_commit``).
    """

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True)

    relationship: str
    cmd: Command = Command.all
    condition_arg: ConditionArg | None = None
    base_name: str | None = None
    allow_bypass_rls: bool = True
    policy_type: PolicyType = PolicyType.permissive
    roles: tuple[str, ...] | None = None

    @pydantic.model_validator(mode="after")
    def _check_roles(self) -> typing.Self:
        if self.roles is not None and not self.roles:
            raise ValueError("roles must not be empty; use None for all roles")
        return self

    @property
    def comparator_names(self) -> tuple[str, ...]:
        """The context fields the policy reads."""
        if self.condition_arg is None:
            return ()
        return (self.condition_arg.comparator_name,)

    def _error(self, mapper: orm.Mapper, message: str) -> ValueError:
        return ValueError(
            f"Cannot build an RLS policy from relationship "
            f"{mapper.class_.__name__}.{self.relationship}: {message}"
        )

    def _clause(
        self, mapper: orm.Mapper
    ) -> tuple[typing.Callable[..., elements.ColumnElement], frozenset[sql.FromClause]]:
        """Return the policy expression (a function of the context value, if
        ``condition_arg`` is set) and the tables its subquery reads."""
        prop = mapper.attrs.get(self.relationship)
        if not isinstance(prop, orm.RelationshipProperty):
            raise self._error(
                mapper,
                f"{mapper.class_.__name__} has no relationship named "
                f"{self.relationship!r} (relationships: "
                f"{sorted(mapper.relationships.keys())})",
            )
        target_mapper = prop.mapper
        if target_mapper.single and target_mapper.inherits is not None:
            # SQLAlchemy restricts such relationships to the subclass with a
            # discriminator criterion that is not part of the join
            # condition, so a policy built from the join alone would also
            # match rows of the other classes sharing the table.
            raise self._error(
                mapper,
                f"it targets {target_mapper.class_.__name__}, which uses "
                "single table inheritance, and the policy cannot include "
                "the criterion that limits rows to that class. Use "
                "Policy.from_sqla instead.",
            )
        local_table = mapper.local_table
        secondary = prop.secondary
        target_tables: set[sql.FromClause] = set(sql_util.find_tables(prop.target))
        allowed = target_tables | {local_table}
        if secondary is not None:
            allowed.add(secondary)
        for element in visitors.iterate(prop.primaryjoin):
            if isinstance(element, sqlalchemy.Column) and element.table not in allowed:
                raise self._error(
                    mapper,
                    f"its join condition uses column {element}, which is not "
                    f"on the {_table_label(local_table)!r} table the policy "
                    "is attached to. Declare the policy on the model whose "
                    "table has the relationship's columns.",
                )

        def to_policy_table(element: typing.Any, **_: typing.Any) -> typing.Any:
            if isinstance(element, sqlalchemy.Column) and element.table is local_table:
                return _policy_table_column(element)
            return None

        primaryjoin = visitors.replacement_traverse(
            prop.primaryjoin, {}, to_policy_table
        )

        def exists(
            from_: sql.FromClause, *where: elements.ColumnElement
        ) -> elements.ColumnElement:
            return (
                sqlalchemy.select(sql.literal_column("1"))
                .select_from(from_)
                .where(*where)
                .exists()
            )

        def check_not_self_referential(tables: abc.Iterable[sql.FromClause]) -> None:
            if local_table in tables:
                raise self._error(
                    mapper,
                    "the relationship is self-referential, so the policy "
                    f"would have to read {_table_label(local_table)!r} from "
                    "its own policy, which Postgres rejects as infinite "
                    "recursion. Use Policy.from_sqla instead.",
                )

        if self.condition_arg is None:
            # Accessible when a related row is visible to the session.
            from_: sql.FromClause = prop.target
            tables = set(target_tables)
            if secondary is not None:
                from_ = secondary.join(prop.target, prop.secondaryjoin)
                tables.add(secondary)
            check_not_self_referential(tables)
            return (lambda: exists(from_, primaryjoin)), frozenset(tables)

        # Accessible when related to the row whose primary key is the
        # context value.
        primary_key = prop.mapper.primary_key
        if len(primary_key) != 1:
            raise self._error(
                mapper,
                "condition_arg is compared with the related row's primary "
                f"key, but {prop.mapper.class_.__name__} has a composite "
                "primary key. Use Policy.from_sqla instead.",
            )
        key_error = self._error(
            mapper,
            "condition_arg is compared with the related row's primary key, "
            "but the relationship does not join on the primary key of "
            f"{prop.mapper.class_.__name__} alone. Use Policy.from_sqla "
            "instead.",
        )
        # The context value replaces the related row, so the join condition
        # must be the key equality alone: any other criteria in it would be
        # dropped, making the policy broader than the relationship.
        not_simple_error = self._error(
            mapper,
            "condition_arg replaces the relationship's join condition with "
            "a comparison of its key column, but the join condition has "
            "other criteria that the policy would drop. Use Policy.from_sqla "
            "instead.",
        )
        if prop.direction is orm_interfaces.MANYTOONE:
            pairs = prop.local_remote_pairs
            if (
                len(pairs) != 1
                or pairs[0][1] is not primary_key[0]
                or pairs[0][0].table is not local_table
            ):
                raise key_error
            if not _is_column_equality(prop.primaryjoin, pairs[0][0], primary_key[0]):
                raise not_simple_error
            foreign_key = _policy_table_column(
                typing.cast(sqlalchemy.Column, pairs[0][0])
            )
            return (lambda value: foreign_key == value), frozenset()
        if prop.direction is orm_interfaces.MANYTOMANY and secondary is not None:
            secondary_pairs = prop.secondary_synchronize_pairs or ()
            if len(secondary_pairs) != 1 or secondary_pairs[0][0] is not primary_key[0]:
                raise key_error
            association_key = secondary_pairs[0][1]
            if prop.secondaryjoin is None or not _is_column_equality(
                prop.secondaryjoin, primary_key[0], association_key
            ):
                raise not_simple_error
            check_not_self_referential({secondary})
            return (
                lambda value: exists(secondary, primaryjoin, association_key == value)
            ), frozenset({secondary})
        raise self._error(
            mapper,
            "condition_arg is only supported for many-to-one and many-to-many "
            f"relationships, not {prop.direction.name}. Omit condition_arg "
            "to make rows accessible when a related row is, or use "
            "Policy.from_sqla.",
        )

    def resolve(self, mapper: orm.Mapper) -> Policy:
        """Build the ``Policy`` for the model mapped by ``mapper``.

        The mappers must be configured (``sqlalchemy.orm.configure_mappers``).
        Raises ``ValueError`` if the relationship cannot be turned into a
        policy, or if the table that decides access (the association table
        of a many-to-many relationship, otherwise the related table) has no
        RLS policies of its own.
        """
        expr, tables = self._clause(mapper)
        prop = mapper.relationships[self.relationship]
        metadata = typing.cast(sqlalchemy.Table, mapper.local_table).metadata
        declared = metadata.info.get(_POLICIES_KEY, {})
        if prop.secondary is not None:
            if not declared.get(_table_label(prop.secondary)):
                raise self._error(
                    mapper,
                    f"the association table {_table_label(prop.secondary)!r} "
                    "has no RLS policies, so anyone who can write to it could "
                    "link rows to gain access to them. Declare its policies "
                    "with rls.register.table_policies.",
                )
        elif self.condition_arg is None and not any(
            declared.get(_table_label(table)) for table in tables
        ):
            raise self._error(
                mapper,
                f"{sorted(_table_label(table) for table in tables)} "
                "have no RLS policies, so every row with a related row "
                "would be accessible. Declare __rls_policies__ on the "
                "related model, or pass condition_arg to compare the "
                "related row's primary key with a context value.",
            )
        name = self.base_name
        if name is None:
            name = "_".join(
                [
                    self.policy_type.value,
                    self.relationship,
                    *self.comparator_names,
                    self.cmd.value,
                ]
            )
        return Policy.from_sqla(
            expr=expr,
            condition_args=[self.condition_arg] if self.condition_arg else [],
            cmd=self.cmd,
            name=name,
            allow_bypass_rls=self.allow_bypass_rls,
            policy_type=self.policy_type,
            roles=self.roles,
        )

    def referenced_tables(self, mapper: orm.Mapper) -> frozenset[str]:
        """Names of the tables read by the policy's subquery, if any."""
        return frozenset(_table_label(table) for table in self._clause(mapper)[1])


def _check_no_recursion(
    relationship_policies: abc.Mapping[
        str, abc.Sequence[tuple[RelationshipPolicy, orm.Mapper]]
    ],
) -> None:
    """Raise ``ValueError`` if relationship policies read each other's tables
    in a cycle, which Postgres rejects when the tables are queried.

    Only ``SELECT`` and ``ALL`` policies apply to the rows a policy's
    subquery reads, so only those can form a cycle.
    """
    reads: dict[str, set[str]] = {}
    for table_name, entries in relationship_policies.items():
        for relationship_policy, mapper in entries:
            if relationship_policy.cmd in (Command.select, Command.all):
                reads.setdefault(table_name, set()).update(
                    relationship_policy.referenced_tables(mapper)
                )

    # Tables whose reads have been fully explored and are known to be
    # acyclic, so shared dependencies are only explored once.
    done: set[str] = set()

    def visit(table_name: str, path: tuple[str, ...]) -> None:
        if table_name in done:
            return
        if table_name in path:
            cycle = [*path[path.index(table_name) :], table_name]
            raise ValueError(
                "RLS relationship policies read each other's tables in a "
                f"cycle ({' -> '.join(cycle)}), which Postgres rejects as "
                "infinite recursion. Derive the policies in one direction "
                "only, e.g. from the child to its parent."
            )
        for other in sorted(reads.get(table_name, ())):
            visit(other, (*path, table_name))
        done.add(table_name)

    for table_name in sorted(reads):
        visit(table_name, ())


def resolved_policies(
    metadata: sqlalchemy.MetaData,
) -> dict[str, list["Policy | ExternalPolicy"]]:
    """Return the policies registered on ``metadata``, keyed by table name.

    Policies declared with ``Policy.from_relationship`` are resolved first,
    which configures the mappers of their registry.  The result is stored, so they are only
    resolved once.
    """
    policies = metadata.info[_POLICIES_KEY]
    pending: dict[str, orm.Mapper] = metadata.info.get(RELATIONSHIP_MAPPERS_KEY, {})
    if pending:
        # Only configure the registries involved, so that unrelated models
        # elsewhere in the process cannot make this fail.
        for registry in {mapper.registry for mapper in pending.values()}:
            registry.configure(cascade=True)
        _check_no_recursion(
            {
                table_name: [
                    (p, mapper)
                    for p in policies[table_name]
                    if isinstance(p, RelationshipPolicy)
                ]
                for table_name, mapper in pending.items()
            }
        )
        resolved = {
            table_name: [
                p.resolve(mapper) if isinstance(p, RelationshipPolicy) else p
                for p in policies[table_name]
            ]
            for table_name, mapper in pending.items()
        }
        for table_name, table_policies in resolved.items():
            check_unique_policy_names(table_name, table_policies)
        policies.update(resolved)
        pending.clear()
    return policies
