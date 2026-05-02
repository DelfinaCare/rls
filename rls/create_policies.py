import sqlalchemy
from sqlalchemy import engine
from sqlalchemy import orm


def create_policies(Base: type[orm.DeclarativeMeta], connection: engine.Connection):
    """Create policies for `Base.metadata.create_all()`."""
    for table, settings in Base.metadata.info["rls_policies"].items():
        if not settings:
            continue
        # enable
        stmt = sqlalchemy.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # force by default
        stmt = sqlalchemy.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # policies
        for ix, policy in enumerate(settings):
            for pol_stmt in policy.get_sql_policies(
                table_name=table, name_suffix=str(ix)
            ):
                connection.execute(pol_stmt)
    connection.commit()
