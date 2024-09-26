from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from rls.schemas import (
    Permissive,
    ExpressionTypes,
    Command,
    ComparatorSource,
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
                    "comparator_name": "sub",
                    "comparator_source": ComparatorSource.bearerTokenPayload,
                    "type": ExpressionTypes.integer,
                }
            ],
            cmd=[Command.all],
            custom_expr="owner_id > {0}",
        )
    ]


# class Item1():
#     __tablename__ = "items1"

#     id = Column(Integer, primary_key=True, index=True)
#     title = Column(String, index=True)
#     description = Column(String)
#     owner_id = Column(Integer, ForeignKey("users.id"))

#     owner = relationship("User")

#     __rls_policies__ = [
#         Permissive(
#             condition_args=[
#                 {
#                     "comparator_name": "sub",
#                     "comparator_source": ComparatorSource.bearerTokenPayload,
#                     "operation": Operation.equality,
#                     "type": ExpressionTypes.integer,
#                     "column_name": "owner_id",
#                 },
#                 {
#                     "comparator_name": "title",
#                     "comparator_source": ComparatorSource.header,
#                     "operation": Operation.equality,
#                     "type": ExpressionTypes.text,
#                     "column_name": "title",
#                 }
#             ],
#             cmd=[Command.all],
#             joined_expr="{0} OR {1}",
#         )
#     ]


# class Item2():
#     __tablename__ = "items2"

#     id = Column(Integer, primary_key=True, index=True)
#     title = Column(String, index=True)
#     description = Column(String)
#     owner_id = Column(Integer, ForeignKey("users.id"))

#     owner = relationship("User")

#     __rls_policies__ = [
#         Permissive(
#             condition_args=[
#                 {
#                     "comparator_name": "sub",
#                     "comparator_source": ComparatorSource.bearerTokenPayload,
#                     "operation": Operation.equality,
#                     "type": ExpressionTypes.integer,
#                     "column_name": "owner_id",
#                 }
#             ],
#             cmd=[Command.select],
#         )
#     ]
