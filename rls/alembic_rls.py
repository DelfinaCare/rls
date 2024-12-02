from typing import Type

from alembic.autogenerate import comparators, renderers
from alembic.operations import MigrateOperation, Operations
from sqlalchemy import text
from sqlalchemy.ext.declarative import DeclarativeMeta
from .utils import generate_rls_policy


############################
# OPERATIONS
############################


@Operations.register_operation("enable_rls")
class EnableRlsOp(MigrateOperation):
    """Enable RowLevelSecurity."""

    def __init__(self, tablename, schemaname=None):
        self.tablename = tablename
        self.schemaname = schemaname

    @classmethod
    def enable_rls(cls, operations, tablename, **kw):
        """Issue a "CREATE SEQUENCE" instruction."""

        op = EnableRlsOp(tablename, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return DisableRlsOp(self.tablename, schemaname=self.schemaname)


@Operations.register_operation("disable_rls")
class DisableRlsOp(MigrateOperation):
    """Drop a SEQUENCE."""

    def __init__(self, tablename, schemaname=None):
        self.tablename = tablename
        self.schemaname = schemaname

    @classmethod
    def disable_rls(cls, operations, tablename, **kw):
        """Issue a "DROP SEQUENCE" instruction."""

        op = DisableRlsOp(tablename, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return EnableRlsOp(self.tablename, schemaname=self.schemaname)


############################
# IMPLEMENTATION
############################


@Operations.implementation_for(EnableRlsOp)
def enable_rls(operations, operation):
    if operation.schemaname is not None:
        name = "%s.%s" % (operation.schemaname, operation.tablename)
    else:
        name = operation.tablename
    operations.execute("ALTER TABLE %s ENABLE ROW LEVEL SECURITY" % name)


@Operations.implementation_for(DisableRlsOp)
def disable_rls(operations, operation):
    if operation.schemaname is not None:
        name = "%s.%s" % (operation.schemaname, operation.sequence_name)
    else:
        name = operation.tablename
    operations.execute("ALTER TABLE %s DISABLE ROW LEVEL SECURITY" % name)


############################
# RENDER
############################


@renderers.dispatch_for(EnableRlsOp)
def render_enable_rls(autogen_context, op):
    return "op.enable_rls(%r)  # type: ignore" % (op.tablename)


@renderers.dispatch_for(DisableRlsOp)
def render_disable_rls(autogen_context, op):
    return "op.disable_rls(%r)  # type: ignore" % (op.tablename)


############################
# COMPARATORS
############################


def check_rls_policies(conn, schemaname, tablename):
    """Retrieve all RLS policies applied to a table from the database."""
    result = conn.execute(
        text(
            f"""SELECT policyname, permissive, roles, qual, with_check
                FROM pg_policies
                WHERE schemaname = '{schemaname if schemaname else "public"}'
                AND tablename = '{tablename}';"""
        )
    ).fetchall()
    # Convert to a list of dictionaries
    columns = ["policyname", "permissive", "roles", "qual", "with_check"]
    result_dicts = [dict(zip(columns, row)) for row in result]

    return result_dicts


def check_table_exists(conn, schemaname, tablename) -> bool:
    result = conn.execute(
        text(
            f"""SELECT EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = '{schemaname if schemaname else "public"}'
    AND table_name = '{tablename}'
);"""
        )
    ).scalar()
    return result


def check_rls_enabled(conn, schemaname, tablename) -> bool:
    result = conn.execute(
        text(
            f"""select relrowsecurity
        from pg_class
        where oid = '{tablename}'::regclass;"""
        )
    ).scalar()
    return result


@comparators.dispatch_for("table")
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
    rls_enabled_meta = tablename in metadata_table.metadata.info["rls_policies"]
    rls_policies_meta = (
        metadata_table.metadata.info["rls_policies"].get(tablename, [])
        if rls_enabled_meta
        else []
    )

    # STEP 4. Enable or disable RLS on the table if needed
    if rls_enabled_meta and not rls_enabled_db:
        modify_ops.ops.append(EnableRlsOp(tablename=tablename, schemaname=schemaname))
    if rls_enabled_db and not rls_enabled_meta:
        modify_ops.ops.append(DisableRlsOp(tablename=tablename, schemaname=schemaname))

    # STEP 5. Compare and manage individual policies (add, remove, update)
    for idx, policy_meta in enumerate(rls_policies_meta):
        policy_meta.get_sql_policies(table_name=tablename, name_suffix=str(idx))
        policy_expr = policy_meta.expression
        for ix, single_policy_name in enumerate(policy_meta.policy_names):
            matched_policy = next(
                (p for p in rls_policies_db if p["policyname"] == single_policy_name),
                None,
            )
            if not matched_policy:
                current_cmd = (
                    policy_meta.cmd[0].value
                    if isinstance(policy_meta.cmd, list)
                    else policy_meta.cmd.value
                )
                # Policy exists in metadata but not in the database, so create it
                modify_ops.ops.append(
                    CreatePolicyOp(
                        table_name=tablename,
                        definition=policy_meta.definition,
                        policy_name=single_policy_name,
                        cmd=current_cmd,
                        expr=policy_expr,
                    )
                )

        for policy_db in rls_policies_db:
            matched_policy = next(
                (p for p in policy_meta.policy_names if p == policy_db["policyname"]),
                None,
            )
            if not matched_policy:
                # Policy exists in the database but not in metadata, so drop it
                modify_ops.ops.append(
                    DropPolicyOp(
                        table_name=tablename,
                        definition=policy_db["permissive"],
                        policy_name=policy_db["policyname"],
                        cmd=policy_db["cmd"],
                        expr=policy_db["qual"],
                    )
                )


@Operations.register_operation("create_policy")
class CreatePolicyOp(MigrateOperation):
    """Operation to create a new RLS policy."""

    def __init__(self, table_name, policy_name, definition, cmd, expr):
        self.table_name = table_name
        self.definition = definition
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name

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


@Operations.register_operation("drop_policy")
class DropPolicyOp(MigrateOperation):
    """Operation to drop an RLS policy."""

    def __init__(self, table_name, policy_name, definition, cmd, expr):
        self.table_name = table_name
        self.definition = definition
        self.cmd = cmd
        self.expr = expr
        self.policy_name = policy_name

    @classmethod
    def drop_policy(cls, operations, table_name, policy_name, **kw):
        op = DropPolicyOp(table_name=table_name, policy_name=policy_name, **kw)
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


@Operations.implementation_for(CreatePolicyOp)
def create_policy(operations, operation):
    table_name = operation.table_name
    policy_name = operation.policy_name
    definition = operation.definition
    cmd = operation.cmd
    expr = operation.expr

    # Generate the SQL to create the policy

    sql = generate_rls_policy(
        cmd=cmd,
        definition=definition,
        policy_name=policy_name,
        table_name=table_name,
        expr=expr,
    )

    operations.execute(sql)


@Operations.implementation_for(DropPolicyOp)
def drop_policy(operations, operation):
    sql = f"DROP POLICY {operation.policy_name} ON {operation.table_name};"
    operations.execute(sql)


@renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(autogen_context, op):
    return f"op.create_policy(table_name={op.table_name!r}, policy_name={op.policy_name!r}, cmd={op.cmd!r}, definition='{op.definition}', expr=\"{op.expr}\") # type: ignore"


@renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(autogen_context, op):
    return f"op.drop_policy(tablename={op.table_name!r}, policyname={op.policy_name!r}) # type: ignore"


def set_metadata_info(Base: Type[DeclarativeMeta]):
    """RLS policies are first added to the Metadata before applied."""
    Base.metadata.info.setdefault("rls_policies", dict())
    for mapper in Base.registry.mappers:
        if not hasattr(mapper.class_, "__rls_policies__"):
            continue

        Base.metadata.info["rls_policies"][mapper.tables[0].fullname] = (
            mapper.class_.__rls_policies__
        )

    return Base
