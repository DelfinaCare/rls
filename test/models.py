from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from rls.schemas import (
    Permissive,
    ExpressionTypes,
    Command,
)


# Base = register_rls(declarative_base())
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User")

    __rls_policies__ = [
        Permissive(
            condition_args=[
                {
                    "comparator_name": "account_id",
                    "type": ExpressionTypes.integer,
                }
            ],
            cmd=[Command.all],
            custom_expr="owner_id > {0}",
        )
    ]
