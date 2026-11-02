import typing
import unittest

import sqlalchemy
from sqlalchemy import orm

from rls import policy
from rls import register
from test import models


class TestRegister(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_policies = [
            policy.Policy.from_sqla(
                expr=lambda x: sqlalchemy.sql.column("id") == x,
                condition_args=[
                    policy.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                cmd=policy.Command.all,
            ),
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

    def test_registers_rls_mode(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class DefaultMode(Base):
            __tablename__ = "default_mode"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies

        class EnableMode(Base):
            __tablename__ = "enable_mode"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies
            __rls_mode__ = policy.RlsMode.enable

        class EnableStringMode(Base):
            __tablename__ = "enable_string_mode"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = self.sample_policies
            __rls_mode__ = "ENABLE"

        self.assertIn(DefaultMode.__tablename__, Base.metadata.tables)
        self.assertIn(EnableMode.__tablename__, Base.metadata.tables)
        self.assertIn(EnableStringMode.__tablename__, Base.metadata.tables)
        self.assertEqual(
            Base.metadata.info["rls_modes"],
            {
                "default_mode": policy.RlsMode.enable_and_force,
                "enable_mode": policy.RlsMode.enable,
                "enable_string_mode": policy.RlsMode.enable,
            },
        )

    def test_invalid_rls_mode_raises(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        with self.assertRaises(ValueError):

            class _InvalidMode(Base):
                __tablename__ = "invalid_mode"
                id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
                __rls_policies__ = self.sample_policies
                __rls_mode__ = "CLEARLY_INVALID_MODE"


if __name__ == "__main__":
    unittest.main()
