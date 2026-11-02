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


def create_policies(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
    connection: engine.Connection,
):
    """Create policies for `Base.metadata.create_all()`."""
    for table, rls_settings in Base.metadata.info["rls_policies"].items():
        if not rls_settings:
            continue
        tablename, schemaname = _split_table_name(Base.metadata, table)
        quoted_table = policy_module.quote_table(tablename, schemaname).replace(
            ":", "\\:"
        )
        # enable
        stmt = sqlalchemy.text(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # force unless the table opted out
        mode = policy_module.RlsMode(
            Base.metadata.info.get("rls_modes", {}).get(
                table, policy_module.DEFAULT_RLS_MODE
            )
        )
        if mode == policy_module.RlsMode.enable_and_force:
            stmt = sqlalchemy.text(
                f"ALTER TABLE {quoted_table} FORCE ROW LEVEL SECURITY;"
            )
            connection.execute(stmt)
        # policies
        for policy in rls_settings:
            connection.execute(
                policy.render_policy(table_name=tablename, schemaname=schemaname)
            )
    connection.commit()
