import typing

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy import sql
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import policy
from rls import register


class Base(orm.DeclarativeBase):
    pass


register.base_wrapper(Base)


class User(sa_asyncio.AsyncAttrs, Base):
    __tablename__ = "users"

    id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.Integer, primary_key=True, index=True
    )
    username: orm.Mapped[str | None] = orm.mapped_column(
        sqlalchemy.String, unique=True, index=True
    )

    __rls_policies__: typing.ClassVar[list[policy.Policy]] = [
        policy.Policy.from_sqla(
            expr=lambda x: sql.column("id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.all,
        ),
    ]


class Item(Base):
    __tablename__ = "items"

    id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.Integer, primary_key=True, index=True
    )
    title: orm.Mapped[str | None] = orm.mapped_column(sqlalchemy.String, index=True)
    description: orm.Mapped[str | None] = orm.mapped_column(sqlalchemy.String)
    owner_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id", ondelete="CASCADE")
    )

    owner: orm.Mapped[User | None] = orm.relationship("User")

    __rls_policies__: typing.ClassVar[list[policy.Policy]] = [
        policy.Policy.from_sqla(
            expr=lambda x: sql.column("owner_id") == x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.all,
        ),
        policy.Policy.from_sqla(
            expr=lambda x: sql.column("owner_id") > x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.select,
        ),
        policy.Policy.from_sqla(
            expr=lambda x: sql.column("owner_id") <= x,
            condition_args=[
                policy.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=policy.Command.all,
        ),
    ]


class SampleRlsContext(pydantic.BaseModel):
    account_id: int | None


class ImmutableSampleRlsContext(pydantic.BaseModel):
    account_id: int | None
    model_config = pydantic.ConfigDict(frozen=True)


class ImmutableEqGuardRlsContext(ImmutableSampleRlsContext):
    def __eq__(self, other: object) -> bool:
        raise AssertionError(
            "Test fixture: equality check should be skipped for immutable contexts"
        )
