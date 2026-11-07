import os
import typing

import sqlalchemy as sa
from alembic import autogenerate
from alembic import operations as alembic_operations
from alembic.autogenerate import api as autogenerate_api
from alembic.operations import ops as migrate_ops

from . import policy

SUPPRESS_ALEMBIC_GENERATION_ENV_VAR = "RLS_SUPPRESS_ALEMBIC_GENERATION"
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def alembic_generation_suppressed() -> bool:
    """Return whether RLS alembic autogenerate is disabled by the environment.

    Set ``RLS_SUPPRESS_ALEMBIC_GENERATION`` to ``1``, ``true``, ``yes`` or
    ``on`` (case-insensitive) to stop autogenerate from emitting any RLS
    operations, e.g. while migrating an existing RLS codebase.
    """
    value = os.environ.get(SUPPRESS_ALEMBIC_GENERATION_ENV_VAR, "")
    return value.strip().lower() in _TRUTHY_ENV_VALUES


@alembic_operations.Operations.register_operation("enable_rls")
class EnableRlsOp(alembic_operations.MigrateOperation):
    """Enable RowLevelSecurity, forcing it unless ``force`` is False."""

    def __init__(
        self, tablename: str, schemaname: str | None = None, force: bool = True
    ) -> None:
        self.tablename = tablename
        self.schemaname = schemaname
        self.force = force

    @classmethod
    def enable_rls(
        cls,
        operations: alembic_operations.Operations,
        tablename: str,
        **kw: typing.Any,
    ) -> None:
        op = EnableRlsOp(tablename, **kw)
        operations.invoke(op)

    def reverse(self) -> "DisableRlsOp":
        # only needed to support autogenerate
        return DisableRlsOp(self.tablename, schemaname=self.schemaname)


@alembic_operations.Operations.register_operation("disable_rls")
class DisableRlsOp(alembic_operations.MigrateOperation):
    """Disable RowLevelSecurity."""

    def __init__(self, tablename: str, schemaname: str | None = None) -> None:
        self.tablename = tablename
        self.schemaname = schemaname

    @classmethod
    def disable_rls(
        cls,
        operations: alembic_operations.Operations,
        tablename: str,
        **kw: typing.Any,
    ) -> None:
        op = DisableRlsOp(tablename, **kw)
        operations.invoke(op)

    def reverse(self) -> EnableRlsOp:
        # only needed to support autogenerate
        return EnableRlsOp(self.tablename, schemaname=self.schemaname)


def _qualified_name(tablename: str, schemaname: str | None) -> str:
    return f"{schemaname}.{tablename}" if schemaname is not None else tablename


def _ddl_table_name(tablename: str, schemaname: str | None) -> str:
    """Quote a table name for use in DDL passed to ``operations.execute``.

    Colons are escaped since Alembic wraps string statements in ``text()``.
    """
    return _escape_colons(policy.quote_table(tablename, schemaname))


def _escape_colons(sql: str) -> str:
    return sql.replace(":", "\\:")


@alembic_operations.Operations.implementation_for(EnableRlsOp)
def enable_rls(
    operations: alembic_operations.Operations, operation: EnableRlsOp
) -> None:
    name = _ddl_table_name(operation.tablename, operation.schemaname)
    operations.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    # Table owners bypass RLS unless it is forced.  Migrations usually run as
    # the table owner, which is often the same role the application uses.
    if operation.force:
        operations.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    else:
        operations.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")


@alembic_operations.Operations.implementation_for(DisableRlsOp)
def disable_rls(
    operations: alembic_operations.Operations, operation: DisableRlsOp
) -> None:
    name = _ddl_table_name(operation.tablename, operation.schemaname)
    operations.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")
    operations.execute(f"ALTER TABLE {name} DISABLE ROW LEVEL SECURITY")


class RLSOp(typing.Protocol):
    """Protocol describing the RLS-specific operations added to Alembic's ``op`` object.

    Use ``cast(RLSOp, op)`` inside generated migration files to get fully-typed
    access to these operations without ``# type: ignore`` suppressions.
    """

    def enable_rls(
        self,
        tablename: str,
        schemaname: str | None = None,
        force: bool = True,
        **kw: typing.Any,
    ) -> None: ...

    def disable_rls(self, tablename: str, **kw: typing.Any) -> None: ...

    def create_policy(
        self,
        table_name: str,
        policy_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        schemaname: str | None = None,
        check_expr: str | None = None,
        roles: typing.Sequence[str] | None = None,
        **kw: typing.Any,
    ) -> None: ...

    def drop_policy(
        self,
        table_name: str,
        policy_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        schemaname: str | None = None,
        check_expr: str | None = None,
        roles: typing.Sequence[str] | None = None,
        **kw: typing.Any,
    ) -> None: ...


def _add_rls_imports(autogen_context: autogenerate_api.AutogenContext) -> None:
    """Inject the imports needed to use ``typing.cast(alembic_ops.RLSOp, op)`` in a migration file."""
    autogen_context.imports.add("import typing")
    autogen_context.imports.add("from rls import alembic_ops")


def _render_schemaname(schemaname: str | None) -> str:
    return f", schemaname={schemaname!r}" if schemaname is not None else ""


@autogenerate.renderers.dispatch_for(EnableRlsOp)
def render_enable_rls(
    autogen_context: autogenerate_api.AutogenContext, op: EnableRlsOp
) -> str:
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).enable_rls({op.tablename!r}"
        f"{_render_schemaname(op.schemaname)}"
        f"{'' if op.force else ', force=False'})"
    )


@autogenerate.renderers.dispatch_for(DisableRlsOp)
def render_disable_rls(
    autogen_context: autogenerate_api.AutogenContext, op: DisableRlsOp
) -> str:
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).disable_rls({op.tablename!r}"
        f"{_render_schemaname(op.schemaname)})"
    )


def _schema_expr(schemaname: str | None) -> typing.Any:
    """Return the schema to look a table up in.

    Unqualified tables live in the connection's ``current_schema()`` (the
    first existing schema on its ``search_path``), not necessarily ``public``.
    """
    return schemaname if schemaname is not None else sa.func.current_schema()


def _roles_from_db(roles: typing.Sequence[str] | None) -> tuple[str, ...] | None:
    """Return the roles of a stored policy, or None if it applies to PUBLIC."""
    if not roles or list(roles) == ["public"]:
        return None
    return tuple(roles)


def check_rls_policies(
    conn: sa.Connection, schemaname: str | None, tablename: str
) -> list[policy.Policy]:
    """Retrieve all RLS policies applied to a table from the database."""
    columns = ["policyname", "permissive", "cmd", "roles", "qual", "with_check"]
    query: sa.Select = (
        sa.select(*[sa.column(c) for c in columns])
        .select_from(sa.table("pg_policies"))
        .where(sa.column("schemaname") == _schema_expr(schemaname))
        .where(sa.column("tablename") == tablename)
    )
    result = conn.execute(query).fetchall()

    policies = []
    for row in result:
        policy_data = dict(zip(columns, row))
        cmd = policy.Command(policy_data["cmd"])
        qual = policy_data["qual"]
        with_check = policy_data["with_check"]
        # INSERT policies only have a WITH CHECK expression; other policies
        # only have a separate one if it differs from USING.
        separate_check = (
            with_check
            if cmd in (policy.Command.all, policy.Command.update)
            and qual is not None
            and with_check != qual
            else None
        )
        p = policy.Policy(
            name=policy_data["policyname"],
            cmd=cmd,
            expr=qual or with_check or "",
            policy_type=policy.PolicyType(policy_data["permissive"]),
            check_expr=separate_check,
            roles=_roles_from_db(policy_data["roles"]),
        )
        policies.append(p)

    return policies


def check_table_exists(
    conn: sa.Connection, schemaname: str | None, tablename: str
) -> bool:
    result = conn.execute(
        sa.select(
            sa.select(sa.literal(1))
            .select_from(sa.table("tables", schema="information_schema"))
            .where(sa.column("table_schema") == _schema_expr(schemaname))
            .where(sa.column("table_name") == tablename)
            .exists()
        )
    ).scalar()
    return bool(result)


def _check_pg_class_flag(
    conn: sa.Connection, schemaname: str | None, tablename: str, flag: str
) -> bool:
    pg_class = sa.table(
        "pg_class",
        sa.column("relname"),
        sa.column("relnamespace"),
        sa.column(flag),
        schema="pg_catalog",
    )
    pg_namespace = sa.table(
        "pg_namespace", sa.column("oid"), sa.column("nspname"), schema="pg_catalog"
    )
    result = conn.execute(
        sa.select(pg_class.c[flag])
        .select_from(
            pg_class.join(pg_namespace, pg_namespace.c.oid == pg_class.c.relnamespace)
        )
        .where(pg_namespace.c.nspname == _schema_expr(schemaname))
        .where(pg_class.c.relname == tablename)
    ).scalar()
    return bool(result)


def check_rls_enabled(
    conn: sa.Connection, schemaname: str | None, tablename: str
) -> bool:
    return _check_pg_class_flag(conn, schemaname, tablename, "relrowsecurity")


def check_rls_forced(
    conn: sa.Connection, schemaname: str | None, tablename: str
) -> bool:
    return _check_pg_class_flag(conn, schemaname, tablename, "relforcerowsecurity")


def _cmd_value(cmd: policy.Command | str) -> str:
    """Return the plain string value of a Command enum member or a plain string."""
    return cmd.value if isinstance(cmd, policy.Command) else cmd


@autogenerate.comparators.dispatch_for("table")
def compare_table_level(
    autogen_context: autogenerate_api.AutogenContext,
    modify_ops: migrate_ops.ModifyTableOps,
    schemaname: str | None,
    tablename: str,
    conn_table: sa.Table | None,
    metadata_table: sa.Table | None,
) -> None:
    if metadata_table is None:
        # The table is being dropped, which also drops its policies.
        return
    if alembic_generation_suppressed():
        return
    connection = autogen_context.connection
    assert connection is not None, "RLS autogenerate requires a database connection"

    # STEP 1. check if the table exists
    table_exists = check_table_exists(connection, schemaname, tablename)

    # STEP 2. Retrieve current RLS policies from the database.  Policies are
    # read even if RLS is disabled on the table, since they still exist and
    # must not be re-created (or must be dropped if no longer wanted).
    rls_enabled_db = (
        check_rls_enabled(connection, schemaname, tablename) if table_exists else False
    )
    rls_policies_db = (
        check_rls_policies(connection, schemaname, tablename) if table_exists else []
    )

    rls_forced_db = (
        check_rls_forced(connection, schemaname, tablename) if rls_enabled_db else False
    )

    # STEP 3. Get RLS policies defined in the metadata.  They are registered
    # under the table's schema-qualified name (``Table.fullname``).
    rls_policies_meta = metadata_table.metadata.info["rls_policies"].get(
        _qualified_name(tablename, schemaname), []
    )
    policy.check_unique_policy_names(
        _qualified_name(tablename, schemaname), rls_policies_meta
    )
    rls_enabled_meta = bool(rls_policies_meta)
    rls_mode_meta = policy.RlsMode(
        metadata_table.metadata.info.get("rls_modes", {}).get(
            _qualified_name(tablename, schemaname), policy.DEFAULT_RLS_MODE
        )
    )
    rls_forced_meta = rls_mode_meta == policy.RlsMode.enable_and_force

    # STEP 4. Enable or disable RLS on the table if needed.  Tables whose
    # FORCE setting does not match the configured mode (e.g. tables enabled
    # without FORCE by older versions of this package) are re-enabled.
    if rls_enabled_meta and not (rls_enabled_db and rls_forced_db == rls_forced_meta):
        modify_ops.ops.append(
            EnableRlsOp(
                tablename=tablename, schemaname=schemaname, force=rls_forced_meta
            )
        )
    if rls_enabled_db and not rls_enabled_meta:
        modify_ops.ops.append(DisableRlsOp(tablename=tablename, schemaname=schemaname))

    # STEP 5. Compare policies by name. Policy names embed a hash of the
    # policy definition, so any change to a policy produces a new name.
    # Postgres rewrites stored policy expressions, so comparing expression
    # strings directly is unreliable.  External policies are managed
    # elsewhere, so they are never created, but are kept if they exist.
    db_policy_names = {p.name for p in rls_policies_db}
    all_metadata_policy_names: set[str] = set()
    create_ops: list[CreatePolicyOp] = []
    for policy_meta in rls_policies_meta:
        all_metadata_policy_names.add(policy_meta.name)
        if isinstance(policy_meta, policy.ExternalPolicy):
            continue
        if policy_meta.name in db_policy_names:
            continue
        # Policy exists in metadata but not in the database, so create it
        create_ops.append(
            CreatePolicyOp(
                table_name=tablename,
                policy_type=policy_meta.policy_type.value,
                policy_name=policy_meta.name,
                cmd=_cmd_value(policy_meta.cmd),
                expr=policy_meta.expr,
                schemaname=schemaname,
                check_expr=policy_meta.check_expr,
                roles=policy_meta.roles,
            )
        )

    # Step 6. Drop policies in the database that are not in the metadata
    # (including outdated versions of changed policies) before creating new ones.
    for policy_db in rls_policies_db:
        if policy_db.name not in all_metadata_policy_names:
            modify_ops.ops.append(
                DropPolicyOp(
                    table_name=tablename,
                    policy_type=policy_db.policy_type.value,
                    policy_name=policy_db.name,
                    cmd=_cmd_value(policy_db.cmd),
                    expr=policy_db.expr,
                    schemaname=schemaname,
                    check_expr=policy_db.check_expr,
                    roles=policy_db.roles,
                )
            )
    modify_ops.ops.extend(create_ops)


class _PolicyOp(alembic_operations.MigrateOperation):
    """Base class of the operations that create or drop an RLS policy."""

    def __init__(
        self,
        table_name: str,
        policy_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        schemaname: str | None = None,
        check_expr: str | None = None,
        roles: typing.Sequence[str] | None = None,
    ) -> None:
        self.table_name = table_name
        self.policy_type = policy_type
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name
        self.schemaname = schemaname
        self.check_expr = check_expr
        self.roles = tuple(roles) if roles is not None else None

    def _kwargs(self) -> dict[str, typing.Any]:
        return {
            "table_name": self.table_name,
            "policy_name": self.policy_name,
            "policy_type": self.policy_type,
            "cmd": self.cmd,
            "expr": self.expr,
            "schemaname": self.schemaname,
            "check_expr": self.check_expr,
            "roles": self.roles,
        }

    def to_policy(self) -> policy.Policy:
        return policy.Policy(
            name=self.policy_name,
            cmd=policy.Command(self.cmd),
            expr=self.expr,
            policy_type=policy.PolicyType(self.policy_type),
            check_expr=self.check_expr,
            roles=self.roles,
        )


@alembic_operations.Operations.register_operation("create_policy")
class CreatePolicyOp(_PolicyOp):
    """Operation to create a new RLS policy."""

    @classmethod
    def create_policy(
        cls,
        operations: alembic_operations.Operations,
        table_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        **kw: typing.Any,
    ) -> None:
        op = CreatePolicyOp(
            table_name=table_name, policy_type=policy_type, cmd=cmd, expr=expr, **kw
        )
        operations.invoke(op)

    def reverse(self) -> "DropPolicyOp":
        return DropPolicyOp(**self._kwargs())

    def to_diff_tuple(self) -> tuple:
        return ("create_policy", self.table_name, self.policy_name)


@alembic_operations.Operations.register_operation("drop_policy")
class DropPolicyOp(_PolicyOp):
    """Operation to drop an RLS policy."""

    @classmethod
    def drop_policy(
        cls,
        operations: alembic_operations.Operations,
        table_name: str,
        policy_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        **kw: typing.Any,
    ) -> None:
        op = DropPolicyOp(
            table_name=table_name,
            policy_name=policy_name,
            policy_type=policy_type,
            cmd=cmd,
            expr=expr,
            **kw,
        )
        operations.invoke(op)

    def reverse(self) -> CreatePolicyOp:
        return CreatePolicyOp(**self._kwargs())

    def to_diff_tuple(self) -> tuple:
        return ("drop_policy", self.table_name, self.policy_name)


@alembic_operations.Operations.implementation_for(CreatePolicyOp)
def create_policy(
    operations: alembic_operations.Operations, operation: CreatePolicyOp
) -> None:
    operations.execute(
        operation.to_policy().render_policy(
            operation.table_name, schemaname=operation.schemaname
        )
    )


@alembic_operations.Operations.implementation_for(DropPolicyOp)
def drop_policy(
    operations: alembic_operations.Operations, operation: DropPolicyOp
) -> None:
    table_name = _ddl_table_name(operation.table_name, operation.schemaname)
    policy_name = _escape_colons(policy.quote_identifier(operation.policy_name))
    operations.execute(f"DROP POLICY {policy_name} ON {table_name}")


def _render_policy_op(
    autogen_context: autogenerate_api.AutogenContext, method: str, op: _PolicyOp
) -> str:
    _add_rls_imports(autogen_context)
    # Optional arguments are only rendered when set, so migrations of
    # policies that do not use them are unchanged.
    optional = ""
    if op.check_expr is not None:
        optional += f", check_expr={op.check_expr!r}"
    if op.roles is not None:
        optional += f", roles={list(op.roles)!r}"
    return (
        f"typing.cast(alembic_ops.RLSOp, op).{method}("
        f"table_name={op.table_name!r}, policy_name={op.policy_name!r}, "
        f"cmd={op.cmd!r}, policy_type={op.policy_type!r}, expr={op.expr!r}"
        f"{optional}{_render_schemaname(op.schemaname)})"
    )


@autogenerate.renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(
    autogen_context: autogenerate_api.AutogenContext, op: CreatePolicyOp
) -> str:
    return _render_policy_op(autogen_context, "create_policy", op)


@autogenerate.renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(
    autogen_context: autogenerate_api.AutogenContext, op: DropPolicyOp
) -> str:
    return _render_policy_op(autogen_context, "drop_policy", op)
