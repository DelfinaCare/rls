from typing import Type

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.declarative import DeclarativeMeta


def create_policies(Base: Type[DeclarativeMeta], connection: Connection):
    """Create policies for `Base.metadata.create_all()`."""
    for table, settings in Base.metadata.info["rls_policies"].items():
        # enable
        stmt = text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # force by default
        stmt = text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        connection.execute(stmt)
        # policies
        for ix, policy in enumerate(settings):
            for pol_stmt in policy.get_sql_policies(
                table_name=table, name_suffix=str(ix)
            ):
                connection.execute(pol_stmt)
    connection.commit()
