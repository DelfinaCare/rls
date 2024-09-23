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
            condition_args=[
                {
                    "comparator_name": "sub",
                    "comparator_source": ComparatorSource.bearerTokenPayload,
                    "operation": Operation.equality,
                    "type": ExpressionTypes.integer,
                    "column_name": "owner_id",
                },
                {
                    "comparator_name": "title",
                    "comparator_source": ComparatorSource.bearerTokenPayload,
                    "operation": Operation.equality,
                    "type": ExpressionTypes.text,
                    "column_name": "title",
                },
                {
                    "comparator_name": "description",
                    "comparator_source": ComparatorSource.bearerTokenPayload,
                    "operation": Operation.equality,
                    "type": ExpressionTypes.text,
                    "column_name": "description",
                },
            ],
            cmd=[Command.all],
            expr="{0} AND ({1} OR {2})",
        )
    ]
