import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy import sql
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import register
from rls import policy


class Base(orm.DeclarativeBase):
    pass


register.base_wrapper(Base)


class User(sa_asyncio.AsyncAttrs, Base):
    __tablename__ = "users"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, index=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True, index=True)

    __rls_policies__ = [
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

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, index=True)
    title = sqlalchemy.Column(sqlalchemy.String, index=True)
    description = sqlalchemy.Column(sqlalchemy.String)
    owner_id = sqlalchemy.Column(
        sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id", ondelete="CASCADE")
    )

    owner = orm.relationship("User")

    __rls_policies__ = [
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
