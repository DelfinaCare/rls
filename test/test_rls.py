import unittest
from pydantic import BaseModel
from testing.postgresql import Postgresql
from sqlalchemy import create_engine, text
from test.models import Base
from rls.register_rls import register_rls
from rls.rls_session import RlsSession
from rls.rls_sessioner import RlsSessioner, ContextGetter
from sqlalchemy.orm import sessionmaker


class TestRLSPolicies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a temporary PostgreSQL instance
        cls.postgresql = Postgresql()
        cls.admin_engine = create_engine(cls.postgresql.url())
        cls.connection = cls.admin_engine.connect()

        # Adds the event listener
        base = register_rls(Base)
        cls.metadata = base.metadata
        base.metadata.create_all(bind=cls.admin_engine)

        # cls.rls_session = RlsSession(bind=cls.engine)

        with cls.connection.begin():
            cls.connection.execute(
                text("""
                    -- Insert user 1
                    INSERT INTO users (username) VALUES ('user1');

                    -- Insert user 2
                    INSERT INTO users (username) VALUES ('user2');


                    -- Insert items for user 1 (id of user1 is assumed to be 1)
                    INSERT INTO items (title, description, owner_id) VALUES
                    ('Item 1 for User 1', 'Description of item 1 for user 1', 1),
                    ('Item 2 for User 1', 'Description of item 2 for user 1', 1);

                    -- Insert items for user 2 (id of user2 is assumed to be 2)
                    INSERT INTO items (title, description, owner_id) VALUES
                    ('Item 1 for User 2', 'Description of item 1 for user 2', 2),
                    ('Item 2 for User 2', 'Description of item 2 for user 2', 2);
                    """)
            )

        # Use a non-superadmin user for the test connection
        non_superadmin_user = "test_user"
        password = "test_password"
        database = cls.postgresql.dsn()["database"]
        port = cls.postgresql.dsn()["port"]
        host = cls.postgresql.dsn()["host"]
        with cls.connection.begin():
            cls.connection.execute(
                text(f"""
                CREATE USER {non_superadmin_user} WITH PASSWORD '{password}';
                GRANT CONNECT ON DATABASE {database} TO {non_superadmin_user};
                GRANT USAGE ON SCHEMA public TO {non_superadmin_user};
                ALTER ROLE {non_superadmin_user} WITH LOGIN;
                GRANT SELECT ON ALL TABLES IN SCHEMA public TO {non_superadmin_user};
                                        """)
            )

            permissions = cls.connection.execute(
                text(
                    "SELECT rolname, rolsuper, rolcanlogin FROM pg_roles WHERE rolname = 'test_user';"
                )
            ).fetchall()
            print("my_user perms:", permissions)

        # Create the engine with the non-superadmin user's credentials
        cls.non_superadmin_engine = create_engine(
            f"postgresql://{non_superadmin_user}:{password}@{host}:{port}/{database}"
        )

        # Set up RLS policies and other test configurations
        # cls.connection = cls.non_superadmin_engine.connect()

    @classmethod
    def tearDownClass(cls):
        cls.connection.close()
        cls.admin_engine.dispose()
        cls.non_superadmin_engine.dispose()
        cls.postgresql.stop()

    # @skip
    def test_policy_creation(self):
        # Check that RLS policies exist in the database
        with self.connection.begin():
            self.connection.execute(text("SET ROLE postgres;"))
            # We checked for two tables at once because tablename is auto applied to policy name so we don't have to check separately
            policies = (
                self.connection.execute(
                    text("""
                SELECT policyname, permissive, qual, with_check, cmd
                FROM pg_policies
                WHERE tablename IN ('items', 'users');
            """)
                )
                .mappings()
                .fetchall()
            )

            self.assertEqual(
                len(policies),
                6,
                "Expected 6 RLS policies to be applied to users and items tables.",
            )
            expected_policies = [
                {
                    "policyname": "items_smaller_than_or_equal_accountid_policy_all_policy_2",
                    "permissive": "PERMISSIVE",
                    "cmd": "ALL",
                    "qual": "((owner_id <= (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_greater_than_accountid_policy_select_policy_1",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id > (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "items_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((owner_id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_update_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "UPDATE",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                    "with_check": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
                {
                    "policyname": "users_equal_to_accountid_policy_select_policy_0",
                    "permissive": "PERMISSIVE",
                    "cmd": "SELECT",
                    "qual": "((id = (COALESCE(current_setting('rls.account_id'::text), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
                },
            ]

            for policy in expected_policies:
                matched_policy = next(
                    (p for p in policies if p["policyname"] == policy["policyname"]),
                    None,
                )

                self.assertIsNotNone(
                    matched_policy,
                    f"Expected policy '{policy['policyname']}' to exist.",
                )

                for key, value in policy.items():
                    self.assertEqual(
                        matched_policy[key],
                        value,
                        f"Expected policy '{policy['policyname']}' to have '{key}'='{value}'.",
                    )

    # @skip
    def test_rls_query_with_rls_session_and_bypass(self):
        class MyContext(BaseModel):
            account_id: int

        context = MyContext(account_id=1)

        rls_session = RlsSession(context=context, bind=self.non_superadmin_engine)

        with rls_session.begin():
            # Test Policy on table users with SELECT where (id = account_id)
            my_user = (
                rls_session.execute(text("SELECT * FROM users;")).mappings().fetchall()
            )
            self.assertEqual(len(my_user), 1, "Expected 1 user to be returned.")
            self.assertEqual(my_user[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                my_user[0]["username"], "user1", "Expected username to be 'user1'."
            )

            # Test bypassing RLS
            with rls_session.bypass_rls():
                my_user = (
                    rls_session.execute(text("SELECT * FROM users;"))
                    .mappings()
                    .fetchall()
                )
                self.assertEqual(len(my_user), 2, "Expected 2 users to be returned.")

    def test_rls_query_with_rls_sessioner_and_bypass(self):
        class ExampleContext(BaseModel):
            account_id: int

        # Concrete implementation of ContextGetter
        class ExampleContextGetter(ContextGetter):
            def get_context(self, *args, **kwargs) -> ExampleContext:
                account_id = kwargs.get("account_id", 1)
                return ExampleContext(account_id=account_id)

        my_context = ExampleContextGetter()

        session_maker = sessionmaker(
            class_=RlsSession,
            autoflush=False,
            autocommit=False,
            bind=self.non_superadmin_engine,
        )

        my_sessioner = RlsSessioner(
            sessionmaker=session_maker, context_getter=my_context
        )

        with my_sessioner(account_id=1) as session:
            res = session.execute(text("SELECT * FROM users")).mappings().fetchall()
            self.assertEqual(len(res), 1, "Expected 1 user to be returned.")
            self.assertEqual(res[0]["id"], 1, "Expected user id to be 1.")
            self.assertEqual(
                res[0]["username"], "user1", "Expected username to be 'user1'."
            )

            with session.bypass_rls():
                res = session.execute(text("SELECT * FROM users")).fetchall()
                self.assertEqual(len(res), 2, "Expected 2 users to be returned.")
