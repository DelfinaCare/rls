import types
import typing
import unittest

import pydantic
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

    def _other_policies(self) -> list[policy.Policy]:
        return [
            policy.Policy.from_sqla(
                expr=lambda x: sqlalchemy.sql.column("id") != x,
                condition_args=[
                    policy.ConditionArg(
                        comparator_name="account_id", type=sqlalchemy.Integer
                    ),
                ],
                cmd=policy.Command.select,
            ),
        ]

    def test_joined_inheritance_registers_each_table(self) -> None:
        parent_policies = self.sample_policies
        child_policies = self._other_policies()

        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class Parent(Base):
            __tablename__ = "parent"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            kind = sqlalchemy.Column(sqlalchemy.String)
            __rls_policies__ = parent_policies
            __mapper_args__ = types.MappingProxyType(
                {"polymorphic_on": kind, "polymorphic_identity": "p"}
            )

        class Child(Parent):
            __tablename__ = "child"
            id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("parent.id"), primary_key=True
            )
            __rls_policies__ = child_policies
            __rls_mode__ = policy.RlsMode.enable
            __mapper_args__ = types.MappingProxyType({"polymorphic_identity": "c"})

        self.assertEqual(
            Base.metadata.info["rls_policies"],
            {"parent": parent_policies, "child": child_policies},
        )
        self.assertEqual(
            Base.metadata.info["rls_modes"],
            {"parent": policy.RlsMode.enable_and_force, "child": policy.RlsMode.enable},
        )

    def test_inherited_policies_are_not_registered_for_subclass(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class Parent(Base):
            __tablename__ = "parent"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            kind = sqlalchemy.Column(sqlalchemy.String)
            __rls_policies__ = self.sample_policies
            __mapper_args__ = types.MappingProxyType(
                {"polymorphic_on": kind, "polymorphic_identity": "p"}
            )

        class JoinedChild(Parent):
            __tablename__ = "joined_child"
            id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("parent.id"), primary_key=True
            )
            __mapper_args__ = types.MappingProxyType({"polymorphic_identity": "j"})

        class SingleChild(Parent):
            __mapper_args__ = types.MappingProxyType({"polymorphic_identity": "s"})

        self.assertIn(JoinedChild.__tablename__, Base.metadata.tables)
        self.assertIsNotNone(SingleChild)
        self.assertEqual(
            Base.metadata.info["rls_policies"], {"parent": self.sample_policies}
        )

    def test_single_table_inheritance_policies_raise(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class Parent(Base):
            __tablename__ = "parent"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            kind = sqlalchemy.Column(sqlalchemy.String)
            __rls_policies__ = self.sample_policies
            __mapper_args__ = types.MappingProxyType(
                {"polymorphic_on": kind, "polymorphic_identity": "p"}
            )

        other_policies = self._other_policies()
        with self.assertRaisesRegex(TypeError, "single-table inheritance"):

            class _SingleChild(Parent):
                __rls_policies__ = other_policies
                __mapper_args__ = types.MappingProxyType({"polymorphic_identity": "s"})

        self.assertEqual(
            Base.metadata.info["rls_policies"], {"parent": self.sample_policies}
        )

    def test_policies_from_unmapped_mixin_are_registered(self) -> None:
        sample_policies = self.sample_policies

        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class RlsMixin:
            __rls_policies__ = sample_policies

        class First(RlsMixin, Base):
            __tablename__ = "first"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Second(RlsMixin, Base):
            __tablename__ = "second"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        self.assertIn(First.__tablename__, Base.metadata.tables)
        self.assertIn(Second.__tablename__, Base.metadata.tables)
        self.assertEqual(
            Base.metadata.info["rls_policies"],
            {"first": sample_policies, "second": sample_policies},
        )

    def test_duplicate_policy_names_raise(self) -> None:
        """Identical policies with the same base name would get the same name."""
        sample_policies = self.sample_policies

        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        with self.assertRaisesRegex(ValueError, "Duplicate RLS policy names"):

            class Dup(Base):
                __tablename__ = "dup"
                id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
                __rls_policies__ = sample_policies * 2


class _Context(pydantic.BaseModel):
    account_id: int


def _policies(comparator_name: str) -> list[policy.Policy | policy.ExternalPolicy]:
    return [
        policy.Policy.from_sqla(
            expr=lambda x: sqlalchemy.sql.column("id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name=comparator_name, type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.all,
        ),
        policy.ExternalPolicy(name="external"),
    ]


class TestValidateContext(unittest.TestCase):
    def test_validate_context_accepts_matching_fields(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class Ok(Base):
            __tablename__ = "ok"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _policies("account_id")

        register.validate_context(Base, _Context)

    def test_validate_context_rejects_typo(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base)

        class Typo(Base):
            __tablename__ = "typo"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _policies("acount_id")

        with self.assertRaisesRegex(ValueError, "acount_id"):
            register.validate_context(Base, _Context)

    def test_validate_context_requires_registration(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        with self.assertRaises(ValueError):
            register.validate_context(Base, _Context)

    def test_base_wrapper_validates_existing_models(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        class Typo(Base):
            __tablename__ = "typo"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _policies("acount_id")

        with self.assertRaisesRegex(ValueError, "acount_id"):
            register.base_wrapper(Base, context_model=_Context)

    def test_base_wrapper_validates_later_models(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base, context_model=_Context)

        class Ok(Base):
            __tablename__ = "ok"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _policies("account_id")

        with self.assertRaisesRegex(ValueError, "acount_id"):

            class Typo(Base):
                __tablename__ = "typo"
                id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
                __rls_policies__ = _policies("acount_id")

    def test_test_models_match_sample_context(self) -> None:
        register.validate_context(models.Base, models.SampleRlsContext)


if __name__ == "__main__":
    unittest.main()
