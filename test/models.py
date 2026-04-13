import typing

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy import sql

from rls import register_rls
from rls import schemas

Base: typing.Any = register_rls.register_rls(orm.declarative_base())


class User(Base):
    __tablename__ = "users"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, index=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True, index=True)

    __rls_policies__ = [
        schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select, schemas.Command.update],
            custom_expr=lambda x: sql.column("id") == x,
            custom_policy_name="equal_to_accountId_policy",
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
        schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select, schemas.Command.update],
            custom_expr=lambda x: sql.column("owner_id") == x,
            custom_policy_name="equal_to_accountId_policy",
        ),
        schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.select],
            custom_expr=lambda x: sql.column("owner_id") > x,
            custom_policy_name="greater_than_accountId_policy",
        ),
        schemas.Permissive(
            condition_args=[
                schemas.ConditionArg(
                    comparator_name="account_id", type=sqlalchemy.Integer
                ),
            ],
            cmd=[schemas.Command.all],
            custom_expr=lambda x: sql.column("owner_id") <= x,
            custom_policy_name="smaller_than_or_equal_accountId_policy",
        ),
    ]


class Account(Base):
    __tablename__ = "accounts"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)


class SampleRlsContext(pydantic.BaseModel):
    account_id: int | None
