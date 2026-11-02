import typing

import sqlalchemy as sa
from alembic import autogenerate
from alembic import operations as alembic_operations

from . import policy


@alembic_operations.Operations.register_operation("enable_rls")
class EnableRlsOp(alembic_operations.MigrateOperation):
    """Enable RowLevelSecurity."""

    def __init__(self, tablename, schemaname=None):
        self.tablename = tablename
        self.schemaname = schemaname

    @classmethod
    def enable_rls(cls, operations, tablename, **kw):
        op = EnableRlsOp(tablename, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return DisableRlsOp(self.tablename, schemaname=self.schemaname)


@alembic_operations.Operations.register_operation("disable_rls")
class DisableRlsOp(alembic_operations.MigrateOperation):
    """Disable RowLevelSecurity."""

    def __init__(self, tablename, schemaname=None):
        self.tablename = tablename
        self.schemaname = schemaname

    @classmethod
    def disable_rls(cls, operations, tablename, **kw):
        op = DisableRlsOp(tablename, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return EnableRlsOp(self.tablename, schemaname=self.schemaname)


def _qualified_name(tablename: str, schemaname: str | None) -> str:
    return f"{schemaname}.{tablename}" if schemaname is not None else tablename


@alembic_operations.Operations.implementation_for(EnableRlsOp)
def enable_rls(operations, operation):
    name = _qualified_name(operation.tablename, operation.schemaname)
    operations.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    # Table owners bypass RLS unless it is forced.  Migrations usually run as
    # the table owner, which is often the same role the application uses.
    operations.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")


@alembic_operations.Operations.implementation_for(DisableRlsOp)
def disable_rls(operations, operation):
    name = _qualified_name(operation.tablename, operation.schemaname)
    operations.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")
    operations.execute(f"ALTER TABLE {name} DISABLE ROW LEVEL SECURITY")


class RLSOp(typing.Protocol):
    """Protocol describing the RLS-specific operations added to Alembic's ``op`` object.

    Use ``cast(RLSOp, op)`` inside generated migration files to get fully-typed
    access to these operations without ``# type: ignore`` suppressions.
    """

    def enable_rls(self, tablename: str, **kw: typing.Any) -> None: ...

    def disable_rls(self, tablename: str, **kw: typing.Any) -> None: ...

    def create_policy(
        self,
        table_name: str,
        policy_name: str,
        policy_type: str,
        cmd: str,
        expr: str,
        schemaname: str | None = None,
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
        **kw: typing.Any,
    ) -> None: ...


def _add_rls_imports(autogen_context: typing.Any) -> None:
    """Inject the imports needed to use ``typing.cast(alembic_ops.RLSOp, op)`` in a migration file."""
    autogen_context.imports.add("import typing")
    autogen_context.imports.add("from rls import alembic_ops")


def _render_schemaname(schemaname: str | None) -> str:
    return f", schemaname={schemaname!r}" if schemaname is not None else ""


@autogenerate.renderers.dispatch_for(EnableRlsOp)
def render_enable_rls(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).enable_rls({op.tablename!r}"
        f"{_render_schemaname(op.schemaname)})"
    )


@autogenerate.renderers.dispatch_for(DisableRlsOp)
def render_disable_rls(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).disable_rls({op.tablename!r}"
        f"{_render_schemaname(op.schemaname)})"
    )


def check_rls_policies(conn, schemaname, tablename) -> list[policy.Policy]:
    """Retrieve all RLS policies applied to a table from the database."""
    columns = ["policyname", "permissive", "cmd", "roles", "qual", "with_check"]
    query: sa.Select = (
        sa.select(*[sa.column(c) for c in columns])
        .select_from(sa.table("pg_policies"))
        .where(sa.column("schemaname") == (schemaname or "public"))
        .where(sa.column("tablename") == tablename)
    )
    result = conn.execute(query).fetchall()

    policies = []
    for row in result:
        policy_data = dict(zip(columns, row))
        p = policy.Policy(
            name=policy_data["policyname"],
            cmd=policy.Command(policy_data["cmd"]),
            expr=policy_data.get("with_check") or policy_data.get("qual") or "",
            policy_type=policy.PolicyType(policy_data["permissive"]),
        )
        policies.append(p)

    return policies


def check_table_exists(conn, schemaname, tablename) -> bool:
    result = conn.execute(
        sa.select(
            sa.select(sa.literal(1))
            .select_from(sa.table("tables", schema="information_schema"))
            .where(sa.column("table_schema") == (schemaname or "public"))
            .where(sa.column("table_name") == tablename)
            .exists()
        )
    ).scalar()
    return result


def _check_pg_class_flag(conn, schemaname, tablename, flag: str) -> bool:
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
        .where(pg_namespace.c.nspname == (schemaname or "public"))
        .where(pg_class.c.relname == tablename)
    ).scalar()
    return bool(result)


def check_rls_enabled(conn, schemaname, tablename) -> bool:
    return _check_pg_class_flag(conn, schemaname, tablename, "relrowsecurity")


def check_rls_forced(conn, schemaname, tablename) -> bool:
    return _check_pg_class_flag(conn, schemaname, tablename, "relforcerowsecurity")


def _cmd_value(cmd: policy.Command | str) -> str:
    """Return the plain string value of a Command enum member or a plain string."""
    return cmd.value if isinstance(cmd, policy.Command) else cmd


@autogenerate.comparators.dispatch_for("table")
def compare_table_level(
    autogen_context, modify_ops, schemaname, tablename, conn_table, metadata_table
):
    if metadata_table is None:
        # The table is being dropped, which also drops its policies.
        return

    # STEP 1. check if the table exists
    table_exists = check_table_exists(autogen_context.connection, schemaname, tablename)

    # STEP 2. Retrieve current RLS policies from the database
    rls_enabled_db = (
        check_rls_enabled(autogen_context.connection, schemaname, tablename)
        if table_exists
        else False
    )
    rls_policies_db = (
        check_rls_policies(autogen_context.connection, schemaname, tablename)
        if rls_enabled_db
        else []
    )

    rls_forced_db = (
        check_rls_forced(autogen_context.connection, schemaname, tablename)
        if rls_enabled_db
        else False
    )

    # STEP 3. Get RLS policies defined in the metadata.  They are registered
    # under the table's schema-qualified name (``Table.fullname``).
    rls_policies_meta = metadata_table.metadata.info["rls_policies"].get(
        _qualified_name(tablename, schemaname), []
    )
    rls_enabled_meta = bool(rls_policies_meta)

    # STEP 4. Enable or disable RLS on the table if needed.  Tables enabled
    # without FORCE (e.g. by older versions of this package) are re-enabled
    # so that RLS also applies to the table owner.
    if rls_enabled_meta and not (rls_enabled_db and rls_forced_db):
        modify_ops.ops.append(EnableRlsOp(tablename=tablename, schemaname=schemaname))
    if rls_enabled_db and not rls_enabled_meta:
        modify_ops.ops.append(DisableRlsOp(tablename=tablename, schemaname=schemaname))

    # STEP 5. Compare policies by name. Policy names embed a hash of the
    # policy definition, so any change to a policy produces a new name.
    # Postgres rewrites stored policy expressions, so comparing expression
    # strings directly is unreliable.
    db_policy_names = {p.name for p in rls_policies_db}
    all_metadata_policy_names: set[str] = set()
    create_ops: list[CreatePolicyOp] = []
    for policy_meta in rls_policies_meta:
        all_metadata_policy_names.add(policy_meta.name)
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
                )
            )
    modify_ops.ops.extend(create_ops)


@alembic_operations.Operations.register_operation("create_policy")
class CreatePolicyOp(alembic_operations.MigrateOperation):
    """Operation to create a new RLS policy."""

    def __init__(
        self, table_name, policy_name, policy_type, cmd, expr, schemaname=None
    ):
        self.table_name = table_name
        self.policy_type = policy_type
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name
        self.schemaname = schemaname

    @classmethod
    def create_policy(cls, operations, table_name, policy_type, cmd, expr, **kw):
        op = CreatePolicyOp(
            table_name=table_name, policy_type=policy_type, cmd=cmd, expr=expr, **kw
        )
        return operations.invoke(op)

    def reverse(self):
        return DropPolicyOp(
            table_name=self.table_name,
            policy_name=self.policy_name,
            policy_type=self.policy_type,
            cmd=self.cmd,
            expr=self.expr,
            schemaname=self.schemaname,
        )

    def to_diff_tuple(self) -> tuple:
        return ("create_policy", self.table_name, self.policy_name)


@alembic_operations.Operations.register_operation("drop_policy")
class DropPolicyOp(alembic_operations.MigrateOperation):
    """Operation to drop an RLS policy."""

    def __init__(
        self, table_name, policy_name, policy_type, cmd, expr, schemaname=None
    ):
        self.table_name = table_name
        self.policy_type = policy_type
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name
        self.schemaname = schemaname

    @classmethod
    def drop_policy(
        cls, operations, table_name, policy_name, policy_type, cmd, expr, **kw
    ):
        op = DropPolicyOp(
            table_name=table_name,
            policy_name=policy_name,
            policy_type=policy_type,
            cmd=cmd,
            expr=expr,
            **kw,
        )
        return operations.invoke(op)

    def reverse(self):
        return CreatePolicyOp(
            table_name=self.table_name,
            policy_name=self.policy_name,
            policy_type=self.policy_type,
            cmd=self.cmd,
            expr=self.expr,
            schemaname=self.schemaname,
        )

    def to_diff_tuple(self) -> tuple:
        return ("drop_policy", self.table_name, self.policy_name)


@alembic_operations.Operations.implementation_for(CreatePolicyOp)
def create_policy(operations, operation):
    p = policy.Policy(
        name=operation.policy_name,
        cmd=policy.Command(operation.cmd),
        expr=operation.expr,
        policy_type=policy.PolicyType(operation.policy_type),
    )
    operations.execute(
        p.render_policy(_qualified_name(operation.table_name, operation.schemaname))
    )


@alembic_operations.Operations.implementation_for(DropPolicyOp)
def drop_policy(operations, operation):
    table_name = _qualified_name(operation.table_name, operation.schemaname)
    sql = f"DROP POLICY {operation.policy_name} ON {table_name};"
    operations.execute(sql)


@autogenerate.renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).create_policy("
        f"table_name={op.table_name!r}, policy_name={op.policy_name!r}, "
        f"cmd={op.cmd!r}, policy_type={op.policy_type!r}, expr={op.expr!r}"
        f"{_render_schemaname(op.schemaname)})"
    )


@autogenerate.renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).drop_policy("
        f"table_name={op.table_name!r}, policy_name={op.policy_name!r}, "
        f"cmd={op.cmd!r}, policy_type={op.policy_type!r}, expr={op.expr!r}"
        f"{_render_schemaname(op.schemaname)})"
    )
