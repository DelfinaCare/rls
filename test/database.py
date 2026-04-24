import sqlalchemy as sa
import testing.postgresql

from test import models


class TestPostgres:
    postgresql: testing.postgresql.Postgresql
    admin_engine: sa.engine.Engine
    url: sa.engine.URL
    admin_url: sa.engine.URL

    def close(self) -> None:
        self.admin_engine.dispose()
        self.postgresql.stop()


def test_postgres_instance() -> TestPostgres:
    """Returns a test postgres instance seeded with data."""
    inst = TestPostgres()
    inst.postgresql = testing.postgresql.Postgresql()
    inst.admin_url = sa.engine.make_url(inst.postgresql.url()).set(
        drivername="postgresql+psycopg"
    )
    inst.admin_engine = sa.create_engine(inst.admin_url)
    connection = inst.admin_engine.connect()
    models.Base.metadata.create_all(bind=inst.admin_engine)

    # Seed data
    user_values = []
    item_values = []
    for user_id in range(1, 3):
        user_values.append({"id": user_id, "username": f"user{user_id}"})
        for item_id in range(1, 3):
            item_values.append(
                {
                    "title": f"Item {item_id} for User {user_id}",
                    "description": f"Description of item {item_id} for User {user_id}",
                    "owner_id": user_id,
                }
            )
    with connection.begin():
        connection.execute(sa.insert(models.User).values(user_values))
        connection.execute(sa.insert(models.Item).values(item_values))
    # Use a non-superadmin user for the test connection
    non_superadmin_user = "test_user"
    password = "test_password"
    database = inst.postgresql.dsn()["database"]
    port = inst.postgresql.dsn()["port"]
    host = inst.postgresql.dsn()["host"]
    with connection.begin():
        connection.execute(
            sa.text(f"""
            CREATE USER {non_superadmin_user} WITH PASSWORD '{password}';
            GRANT CONNECT ON DATABASE {database} TO {non_superadmin_user};
            GRANT USAGE ON SCHEMA public TO {non_superadmin_user};
            ALTER ROLE {non_superadmin_user} WITH LOGIN;
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO {non_superadmin_user};
                                    """)
        )
    connection.close()
    inst.url = sa.engine.make_url(
        f"postgresql+psycopg://{non_superadmin_user}:{password}@{host}:{port}/{database}"
    )
    return inst
