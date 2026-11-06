import sqlalchemy
from sqlalchemy import engine
from sqlalchemy import orm

from rls import policy as policy_module


def _split_table_name(
    metadata: sqlalchemy.MetaData, fullname: str
) -> tuple[str, str | None]:
    """Return the (table name, schema name) for a key of ``rls_policies``."""
    table = metadata.tables.get(fullname)
    if table is not None:
        return table.name, table.schema
    schemaname, _, tablename = fullname.rpartition(".")
    return tablename, schemaname or None


def create_policies_no_commit(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
    connection: engine.Connection,
):
    """Enable RLS and create policies for `Base.metadata.create_all()`.

    ``Base`` must have been registered with ``rls.register.base_wrapper``.
    This is idempotent: each policy is dropped (if it exists) before it is
    created, so it can be called again to re-apply the policies.  Policies
    that are no longer declared are not dropped.  Transaction control is
    left to the caller, e.g. wrap the call in ``connection.begin()``.
    """
    if "rls_policies" not in Base.metadata.info:
        raise ValueError(
            f"{Base.__name__} is not registered for RLS; call "
            "rls.register.base_wrapper(Base) before create_policies_no_commit."
        )
    for table, rls_settings in Base.metadata.info["rls_policies"].items():
        if not rls_settings:
            continue
        policy_module.check_unique_policy_names(table, rls_settings)
        tablename, schemaname = _split_table_name(Base.metadata, table)
        quoted_table = policy_module.quote_table(tablename, schemaname).replace(
            ":", "\\:"
        )
        # enable
        stmt = sqlalchemy.text(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY")
        connection.execute(stmt)
        # force unless the table opted out (NO FORCE keeps re-runs consistent)
        mode = policy_module.RlsMode(
            Base.metadata.info.get("rls_modes", {}).get(
                table, policy_module.DEFAULT_RLS_MODE
            )
        )
        force = (
            "FORCE" if mode == policy_module.RlsMode.enable_and_force else "NO FORCE"
        )
        stmt = sqlalchemy.text(f"ALTER TABLE {quoted_table} {force} ROW LEVEL SECURITY")
        connection.execute(stmt)
        # policies (external policies are managed elsewhere)
        for policy in rls_settings:
            if isinstance(policy, policy_module.ExternalPolicy):
                continue
            quoted_policy = policy_module.quote_identifier(policy.name).replace(
                ":", "\\:"
            )
            connection.execute(
                sqlalchemy.text(
                    f"DROP POLICY IF EXISTS {quoted_policy} ON {quoted_table}"
                )
            )
            connection.execute(
                policy.render_policy(table_name=tablename, schemaname=schemaname)
            )
