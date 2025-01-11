from typing import Type

import sqlalchemy as sa
from alembic.autogenerate import comparators, renderers
from alembic.operations import MigrateOperation, Operations
from sqlalchemy.dialects import postgresql as pg_dialect
from sqlalchemy.ext.declarative import DeclarativeMeta

from .schemas import Command, Policy
from .utils import generate_rls_policy, policy_changed_checker

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
        op = EnableRlsOp(tablename, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return DisableRlsOp(self.tablename, schemaname=self.schemaname)


@Operations.register_operation("disable_rls")
class DisableRlsOp(MigrateOperation):
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


def check_rls_policies(conn, schemaname, tablename) -> list[Policy]:
    """Retrieve all RLS policies applied to a table from the database."""
    columns = ["policyname", "permissive", "cmd", "roles", "qual", "with_check"]
    query = (
        sa.select(*[sa.column(c) for c in columns])
        .select_from(sa.table("pg_policies"))
        .where(sa.column("schemaname") == (schemaname or "public"))
        .where(sa.column("tablename") == tablename)
    )
    result = conn.execute(query).fetchall()
    # Convert to a list of dictionaries
    # result_dicts = [dict(zip(columns, row)) for row in result]

    # Convert query result to a list of Policy objects
    policies = []
    for row in result:
        policy_data = dict(zip(columns, row))

        # Map the database fields to Policy attributes
        policy = Policy(
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
    )
    return result


def check_rls_enabled(conn, schemaname, tablename) -> bool:
    fq_tablename = sa.literal(f"{schemaname}.tablename" if schemaname else tablename)
    result = conn.execute(
        sa.select(sa.column("relrowsecurity"))
        .select_from(sa.table("pg_class"))
        .where(sa.column("oid") == sa.cast(fq_tablename, pg_dialect.REGCLASS))
    )
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
            current_cmd = ""
            if isinstance(policy_meta.cmd, list):
                if isinstance(policy_meta.cmd[ix], Command):
                    current_cmd = policy_meta.cmd[ix].value
                else:
                    current_cmd = policy_meta.cmd[ix]
            else:
                if isinstance(policy_meta.cmd, Command):
                    current_cmd = policy_meta.cmd.value
                else:
                    current_cmd = policy_meta.cmd

            matched_policy = next(
                (
                    p
                    for p in rls_policies_db
                    if p.custom_policy_name == single_policy_name
                ),
                None,
            )
            if not matched_policy:
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

            else:
                # Policy exists in both metadata and database, so check if it needs to be updated
                # Notice: Matched policy is db policy
                tmp_policy_meta = policy_meta.model_copy()
                tmp_policy_meta.cmd = Command(current_cmd)
                if not policy_changed_checker(
                    db_policy=matched_policy, metadata_policy=tmp_policy_meta
                ):
                    # Policy has changed, so drop and recreate it
                    modify_ops.ops.append(
                        DropPolicyOp(
                            table_name=tablename,
                            definition=matched_policy.definition,
                            policy_name=matched_policy.custom_policy_name,
                            cmd=current_cmd,
                            expr=matched_policy.expression,
                        )
                    )
                    modify_ops.ops.append(
                        CreatePolicyOp(
                            table_name=tablename,
                            definition=policy_meta.definition,
                            policy_name=single_policy_name,
                            cmd=current_cmd,
                            expr=policy_expr,
                        )
                    )

    # Step 5.5 : Get all policy meta names
    all_metadata_policy_names = []
    for policy_meta in rls_policies_meta:
        policy_meta.get_sql_policies(table_name=tablename)
        all_metadata_policy_names.extend(policy_meta.policy_names)

    # Step 6. Check if there are any policies in the database that are not in the metadata
    for policy_db in rls_policies_db:
        matched_policy = next(
            (p for p in all_metadata_policy_names if p == policy_db.custom_policy_name),
            None,
        )
        if not matched_policy:
            # Policy exists in the database but not in metadata, so drop it
            modify_ops.ops.append(
                DropPolicyOp(
                    table_name=tablename,
                    definition=policy_db.definition,
                    policy_name=policy_db.custom_policy_name,
                    cmd=policy_db.cmd.value,
                    expr=policy_db.expression,
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
    return f"op.drop_policy(table_name={op.table_name!r}, policy_name={op.policy_name!r}, cmd={op.cmd!r}, definition='{op.definition}', expr=\"{op.expr}\") # type: ignore"


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
