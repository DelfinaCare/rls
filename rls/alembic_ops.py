import typing

import sqlalchemy as sa
from alembic import autogenerate
from alembic import operations as alembic_operations
from sqlalchemy.dialects import postgresql as pg_dialect

from . import _sql_gen
from . import schemas


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


@alembic_operations.Operations.implementation_for(EnableRlsOp)
def enable_rls(operations, operation):
    if operation.schemaname is not None:
        name = f"{operation.schemaname}.{operation.tablename}"
    else:
        name = operation.tablename
    operations.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")


@alembic_operations.Operations.implementation_for(DisableRlsOp)
def disable_rls(operations, operation):
    if operation.schemaname is not None:
        name = f"{operation.schemaname}.{operation.tablename}"
    else:
        name = operation.tablename
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
        definition: str,
        cmd: str,
        expr: str,
        allow_bypass_rls: bool = True,
        **kw: typing.Any,
    ) -> None: ...

    def drop_policy(
        self,
        table_name: str,
        policy_name: str,
        definition: str,
        cmd: str,
        expr: str,
        **kw: typing.Any,
    ) -> None: ...


def _add_rls_imports(autogen_context: typing.Any) -> None:
    """Inject the imports needed to use ``typing.cast(alembic_ops.RLSOp, op)`` in a migration file."""
    autogen_context.imports.add("import typing")
    autogen_context.imports.add("from rls import alembic_ops")


@autogenerate.renderers.dispatch_for(EnableRlsOp)
def render_enable_rls(autogen_context, op):
    _add_rls_imports(autogen_context)
    return f"typing.cast(alembic_ops.RLSOp, op).enable_rls({op.tablename!r})"


@autogenerate.renderers.dispatch_for(DisableRlsOp)
def render_disable_rls(autogen_context, op):
    _add_rls_imports(autogen_context)
    return f"typing.cast(alembic_ops.RLSOp, op).disable_rls({op.tablename!r})"


def check_rls_policies(conn, schemaname, tablename) -> list[schemas.Policy]:
    """Retrieve all RLS policies applied to a table from the database."""
    columns = ["policyname", "permissive", "cmd", "roles", "qual", "with_check"]
    query: sa.Select = (
        sa.select(*[sa.column(c) for c in columns])
        .select_from(sa.table("pg_policies"))
        .where(sa.column("schemaname") == (schemaname or "public"))
        .where(sa.column("tablename") == tablename)
    )
    result = conn.execute(query).fetchall()

    # Convert query result to a list of Policy objects
    policies = []
    for row in result:
        policy_data = dict(zip(columns, row))

        # Map the database fields to Policy attributes
        policy = schemas.Policy(
            definition=policy_data.get("permissive", ""),
            cmd=policy_data.get("cmd", ""),
            custom_policy_name=policy_data.get("policyname", ""),
        )

        # Set the expression (or any other additional fields) as needed
        policy.expression = policy_data.get("with_check", "") or policy_data.get(
            "qual", ""
        )

        policies.append(policy)

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


def check_rls_enabled(conn, schemaname, tablename) -> bool:
    fq_tablename = sa.literal(f"{schemaname}.{tablename}" if schemaname else tablename)
    result = conn.execute(
        sa.select(sa.column("relrowsecurity"))
        .select_from(sa.table("pg_class"))
        .where(sa.column("oid") == sa.cast(fq_tablename, pg_dialect.REGCLASS))
    ).scalar()
    return result


def _cmd_value(cmd: schemas.Command | str) -> str:
    """Return the plain string value of a Command enum member or a plain string."""
    return cmd.value if isinstance(cmd, schemas.Command) else cmd


@autogenerate.comparators.dispatch_for("table")
def compare_table_level(
    autogen_context, modify_ops, schemaname, tablename, conn_table, metadata_table
):
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

    # STEP 3. Get RLS policies defined in the metadata
    rls_policies_meta = metadata_table.metadata.info["rls_policies"].get(tablename, [])
    rls_enabled_meta = bool(rls_policies_meta)

    # STEP 4. Enable or disable RLS on the table if needed
    if rls_enabled_meta and not rls_enabled_db:
        modify_ops.ops.append(EnableRlsOp(tablename=tablename, schemaname=schemaname))
    if rls_enabled_db and not rls_enabled_meta:
        modify_ops.ops.append(DisableRlsOp(tablename=tablename, schemaname=schemaname))

    # STEP 5. Compare policies by name. Policy names embed a hash of the
    # generated policy SQL, so any change to a policy produces a new name.
    # Postgres rewrites stored policy expressions, so comparing expression
    # strings directly is unreliable.
    db_policy_names = {p.custom_policy_name for p in rls_policies_db}
    all_metadata_policy_names: set[str] = set()
    create_ops: list[CreatePolicyOp] = []
    for idx, policy_meta in enumerate(rls_policies_meta):
        policy_meta.get_sql_policies(table_name=tablename, name_suffix=str(idx))
        all_metadata_policy_names.update(policy_meta.policy_names)
        policy_expr = policy_meta.expression
        for ix, single_policy_name in enumerate(policy_meta.policy_names):
            if single_policy_name in db_policy_names:
                continue
            if isinstance(policy_meta.cmd, list):
                current_cmd = _cmd_value(policy_meta.cmd[ix])
            else:
                current_cmd = _cmd_value(policy_meta.cmd)
            # Policy exists in metadata but not in the database, so create it
            create_ops.append(
                CreatePolicyOp(
                    table_name=tablename,
                    definition=policy_meta.definition,
                    policy_name=single_policy_name,
                    cmd=current_cmd,
                    expr=policy_expr,
                    allow_bypass_rls=policy_meta.allow_bypass_rls,
                )
            )

    # Step 6. Drop policies in the database that are not in the metadata
    # (including outdated versions of changed policies) before creating new ones.
    for policy_db in rls_policies_db:
        if policy_db.custom_policy_name not in all_metadata_policy_names:
            modify_ops.ops.append(
                DropPolicyOp(
                    table_name=tablename,
                    definition=policy_db.definition,
                    policy_name=policy_db.custom_policy_name,
                    cmd=policy_db.cmd.value,
                    expr=policy_db.expression,
                )
            )
    modify_ops.ops.extend(create_ops)


@alembic_operations.Operations.register_operation("create_policy")
class CreatePolicyOp(alembic_operations.MigrateOperation):
    """Operation to create a new RLS policy."""

    def __init__(
        self, table_name, policy_name, definition, cmd, expr, allow_bypass_rls=True
    ):
        self.table_name = table_name
        self.definition = definition
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name
        self.allow_bypass_rls = allow_bypass_rls

    @classmethod
    def create_policy(cls, operations, table_name, definition, cmd, expr, **kw):
        op = CreatePolicyOp(
            table_name=table_name, definition=definition, cmd=cmd, expr=expr, **kw
        )
        return operations.invoke(op)

    def reverse(self):
        return DropPolicyOp(
            table_name=self.table_name,
            policy_name=self.policy_name,
            definition=self.definition,
            cmd=self.cmd,
            expr=self.expr,
        )


@alembic_operations.Operations.register_operation("drop_policy")
class DropPolicyOp(alembic_operations.MigrateOperation):
    """Operation to drop an RLS policy."""

    def __init__(self, table_name, policy_name, definition, cmd, expr):
        self.table_name = table_name
        self.definition = definition
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name

    @classmethod
    def drop_policy(
        cls, operations, table_name, policy_name, definition, cmd, expr, **kw
    ):
        op = DropPolicyOp(
            table_name=table_name,
            policy_name=policy_name,
            definition=definition,
            cmd=cmd,
            expr=expr,
            **kw,
        )
        return operations.invoke(op)

    def reverse(self):
        # You need the original policy metadata to recreate it, so this part is context-dependent.
        return CreatePolicyOp(
            table_name=self.table_name,
            policy_name=self.policy_name,
            definition=self.definition,
            cmd=self.cmd,
            expr=self.expr,
        )


@alembic_operations.Operations.implementation_for(CreatePolicyOp)
def create_policy(operations, operation):
    table_name = operation.table_name
    policy_name = operation.policy_name
    definition = operation.definition
    cmd = operation.cmd
    expr = operation.expr
    allow_bypass_rls = operation.allow_bypass_rls

    # Generate the SQL to create the policy
    sql = _sql_gen.generate_rls_policy(
        cmd=cmd,
        definition=definition,
        policy_name=policy_name,
        table_name=table_name,
        expr=expr,
        allow_bypass_rls=allow_bypass_rls,
    )

    operations.execute(sql)


@alembic_operations.Operations.implementation_for(DropPolicyOp)
def drop_policy(operations, operation):
    sql = f"DROP POLICY {operation.policy_name} ON {operation.table_name};"
    operations.execute(sql)


@autogenerate.renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).create_policy("
        f"table_name={op.table_name!r}, policy_name={op.policy_name!r}, "
        f"cmd={op.cmd!r}, definition={op.definition!r}, expr={op.expr!r}, "
        f"allow_bypass_rls={op.allow_bypass_rls!r})"
    )


@autogenerate.renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(autogen_context, op):
    _add_rls_imports(autogen_context)
    return (
        f"typing.cast(alembic_ops.RLSOp, op).drop_policy("
        f"table_name={op.table_name!r}, policy_name={op.policy_name!r}, "
        f"cmd={op.cmd!r}, definition={op.definition!r}, expr={op.expr!r})"
    )
