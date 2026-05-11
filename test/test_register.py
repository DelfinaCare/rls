import typing
import unittest

import sqlalchemy
from sqlalchemy import orm

from rls import register
from rls import schemas
from test import models


class TestRegister(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_policies = [
            schemas.Permissive(
                condition_args=[
                    schemas.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                cmd=[schemas.Command.select],
                custom_expr=lambda x: sqlalchemy.sql.column("id") == x,
            )
        ]

    def test_models_populates_rls_policies(self):

        self.assertIn("rls_policies", models.Base.metadata.info)
        self.assertIn("users", models.Base.metadata.info["rls_policies"])
        self.assertIn("items", models.Base.metadata.info["rls_policies"])

    def test_skips_models_without_rls_policies(self) -> None:
        """Models without __rls_policies__ should not appear in the dict."""

        class Base(orm.DeclarativeBase):
            pass

        class NoRls(Base):
            __tablename__ = "no_rls"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class WithRls(Base):
            __tablename__ = "with_rls"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        register.base_wrapper(Base)
        self.assertIn(NoRls.__tablename__, Base.metadata.tables)
        self.assertEqual(list(Base.metadata.info["rls_policies"].keys()), ["with_rls"])

    def test_declarative_base_before_after_wrapper(self) -> None:
        Base: typing.Any = orm.declarative_base()

        class DefinedBeforeWrapper(Base):
            __tablename__ = "defined_before"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        wrap_result = register.base_wrapper(Base)
        self.assertIs(Base, wrap_result)

        class DefinedAfterWrapper(Base):
            __tablename__ = "defined_after"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        self.assertIn(DefinedBeforeWrapper.__tablename__, Base.metadata.tables)
        self.assertIn(DefinedAfterWrapper.__tablename__, Base.metadata.tables)
        self.assertEqual(
            list(Base.metadata.info["rls_policies"].keys()),
            ["defined_before", "defined_after"],
        )

    def test_declarative_meta_before_after_wrapper(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        class DefinedBeforeWrapper(Base):
            __tablename__ = "defined_before"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        wrap_result = register.base_wrapper(Base)
        self.assertIs(Base, wrap_result)

        class DefinedAfterWrapper(Base):
            __tablename__ = "defined_after"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        self.assertIn(DefinedBeforeWrapper.__tablename__, Base.metadata.tables)
        self.assertIn(DefinedAfterWrapper.__tablename__, Base.metadata.tables)
        self.assertEqual(
            list(Base.metadata.info["rls_policies"].keys()),
            ["defined_before", "defined_after"],
        )


if __name__ == "__main__":
    unittest.main()
