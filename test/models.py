from sqlalchemy import Column, Integer, String, ForeignKey, func
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import column
from typing import Any
from rls.schemas import Permissive, Command

# To avoid deletion by pre-commit hooks
_Any = Any

Base = declarative_base()  # type: Any


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    owner = relationship("User")

    __rls_policies__ = [
        Permissive(
            condition_args=[
                {
                    "comparator_name": "account_id",
                    "type": Integer,
                }
            ],
            cmd=[Command.all],
            custom_expr=column("owner_id")
            > func.current_setting("account_id").cast(Integer),
        )
    ]
