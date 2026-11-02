import sqlalchemy
from sqlalchemy import engine
from sqlalchemy import orm

from rls import policy as policy_module


def create_policies(
    Base: type[orm.DeclarativeMeta] | type[orm.DeclarativeBase],
    connection: engine.Connection,
):
    """Create policies for `Base.metadata.create_all()`."""
    for table, rls_settings in Base.metadata.info["rls_policies"].items():
        if not rls_settings:
            continue
        # enable
        stmt = sqlalchemy.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # force unless the table opted out
        mode = policy_module.RlsMode(
            Base.metadata.info.get("rls_modes", {}).get(
                table, policy_module.DEFAULT_RLS_MODE
            )
        )
        if mode == policy_module.RlsMode.enable_and_force:
            stmt = sqlalchemy.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
            connection.execute(stmt)
        # policies
        for policy in rls_settings:
            connection.execute(policy.render_policy(table_name=table))
    connection.commit()
