from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from rls.schemas import (
    Permissive,
    Operation,
    ExpressionTypes,
    Command,
    ComparatorSource,
)
from rls.register_rls import register_rls
from rls.database import RlsBase

# Register RLS policies
register_rls(RlsBase)


class User(RlsBase):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)


class Item(RlsBase):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User")

    __rls_policies__ = [
        Permissive(
            condition_args={
                "comparator_name": "sub",
                "comparator_source": ComparatorSource.bearerTokenPayload,
                "operation": Operation.equality,
                "type": ExpressionTypes.integer,
                "column_name": "owner_id",
                # "expr": "&column_name& = current_setting('&comparator_name&')::UUID"
                # TODO: how to parse the comparator name from expr
                # IDEA: may give us a custom function to parse from the comparator he customized
            },
            cmd=[Command.all],
        )
    ]
