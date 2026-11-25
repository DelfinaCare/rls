import typing
import unittest

import pydantic
import sqlalchemy
import testing.postgresql
from alembic import autogenerate
from alembic import migration
from alembic import operations as alembic_operations
from alembic.operations import ops as alembic_ops_module
from sqlalchemy import exc
from sqlalchemy import orm
from sqlalchemy import sql

from rls import alembic_ops
from rls import create_policies
from rls import policy
from rls import register
from rls import session

_ACCOUNT_ID = policy.ConditionArg(comparator_name="account_id", type=sqlalchemy.Integer)
_ACCOUNT_SETTING = (
    "CAST(nullif(current_setting('rls.account_id', true), '') AS INTEGER)"
)
_BYPASS = (
    " OR CAST(nullif(current_setting('rls.bypass_rls', true), '') AS BOOLEAN) = true"
)

_Policies = list[policy.Policy | policy.ExternalPolicy | policy.RelationshipPolicy]


def _owner_policy(
    column: str = "id", cmd: policy.Command = policy.Command.all
) -> policy.Policy:
    return policy.Policy.from_sqla(
        expr=lambda x: sql.column(column) == x,
        condition_args=[_ACCOUNT_ID],
        cmd=cmd,
    )


def _owner_policies(column: str = "id") -> _Policies:
    return [_owner_policy(column)]


def _cmds(base: typing.Any, table: str) -> list[policy.Command]:
    return [
        typing.cast(policy.Policy, p).cmd
        for p in policy.resolved_policies(base.metadata)[table]
    ]


def _new_base() -> typing.Any:
    class Base(orm.DeclarativeBase):
        pass

    register.base_wrapper(Base)
    return Base


def _exprs(base: type[orm.DeclarativeBase], table: str) -> list[str]:
    """The policy expressions of a table, with whitespace normalised."""
    return [
        " ".join(typing.cast(policy.Policy, p).expr.split())
        for p in policy.resolved_policies(base.metadata)[table]
    ]


def _library(
    book_policies: _Policies,
    author_policies: _Policies | None = None,
    tag_policies: _Policies | None = None,
    schema: str | None = None,
    link_policies: list[policy.Policy | policy.ExternalPolicy] | None = None,
) -> typing.Any:
    """Authors have many books; books and tags are many-to-many."""
    Base: typing.Any = _new_base()
    prefix = f"{schema}." if schema else ""
    table_args = {"schema": schema} if schema else {}

    book_tags = sqlalchemy.Table(
        "book_tags",
        Base.metadata,
        sqlalchemy.Column(
            "book_id", sqlalchemy.ForeignKey(f"{prefix}books.id"), primary_key=True
        ),
        sqlalchemy.Column(
            "tag_id", sqlalchemy.ForeignKey(f"{prefix}tags.id"), primary_key=True
        ),
        schema=schema,
    )
    if link_policies is None:
        link_policies = [_owner_policy("tag_id")]
    if link_policies:
        register.table_policies(book_tags, link_policies)

    class Book(Base):
        __tablename__ = "books"
        __table_args__ = table_args
        id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
        author_id = sqlalchemy.Column(
            sqlalchemy.Integer, sqlalchemy.ForeignKey(f"{prefix}authors.id")
        )
        # The related models are defined below: policies are resolved lazily.
        author = orm.relationship("Author", back_populates="books")
        tags = orm.relationship("Tag", secondary=book_tags)
        __rls_policies__ = book_policies

    class Author(Base):
        __tablename__ = "authors"
        __table_args__ = table_args
        id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
        books = orm.relationship("Book", back_populates="author")
        __rls_policies__ = (
            _owner_policies() if author_policies is None else author_policies
        )

    class Tag(Base):
        __tablename__ = "tags"
        __table_args__ = table_args
        id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
        __rls_policies__ = _owner_policies() if tag_policies is None else tag_policies

    # The class registry only holds weak references, and Book refers to the
    # other models by name, so they are kept alive until resolved.
    Base.models = (Book, Author, Tag)
    return Base


class TestRelationshipPolicyExpressions(unittest.TestCase):
    def test_many_to_one_follows_related_row(self) -> None:
        Base = _library([policy.Policy.from_relationship("author")])
        self.assertEqual(
            _exprs(Base, "books"),
            [
                "(EXISTS (SELECT 1 FROM authors "
                "WHERE authors.id = books.author_id))" + _BYPASS
            ],
        )

    def test_many_to_one_with_condition_arg_compares_foreign_key(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("author", condition_arg=_ACCOUNT_ID)]
        )
        self.assertEqual(
            _exprs(Base, "books"),
            [f"books.author_id = {_ACCOUNT_SETTING}" + _BYPASS],
        )

    def test_many_to_many_follows_related_rows(self) -> None:
        Base = _library([policy.Policy.from_relationship("tags")])
        self.assertEqual(
            _exprs(Base, "books"),
            [
                "(EXISTS (SELECT 1 FROM book_tags "
                "JOIN tags ON tags.id = book_tags.tag_id "
                "WHERE books.id = book_tags.book_id))" + _BYPASS
            ],
        )

    def test_many_to_many_with_condition_arg_reads_association_table(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("tags", condition_arg=_ACCOUNT_ID)]
        )
        self.assertEqual(
            _exprs(Base, "books"),
            [
                "(EXISTS (SELECT 1 FROM book_tags "
                "WHERE books.id = book_tags.book_id "
                f"AND book_tags.tag_id = {_ACCOUNT_SETTING}))" + _BYPASS
            ],
        )

    def test_one_to_many_follows_related_rows(self) -> None:
        Base = _library(
            book_policies=_owner_policies("author_id"),
            author_policies=[policy.Policy.from_relationship("books")],
        )
        self.assertEqual(
            _exprs(Base, "authors"),
            [
                "(EXISTS (SELECT 1 FROM books "
                "WHERE authors.id = books.author_id))" + _BYPASS
            ],
        )

    def test_command(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship("tags"),
                policy.Policy.from_relationship("author", cmd=policy.Command.insert),
            ]
        )
        self.assertEqual(
            _cmds(Base, "books"), [policy.Command.all, policy.Command.insert]
        )

    def test_schema_qualified_tables(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship("author"),
                policy.Policy.from_relationship(
                    "author", cmd=policy.Command.select, condition_arg=_ACCOUNT_ID
                ),
            ],
            schema="lib",
        )
        self.assertEqual(
            _exprs(Base, "lib.books"),
            [
                "(EXISTS (SELECT 1 FROM lib.authors "
                "WHERE lib.authors.id = lib.books.author_id))" + _BYPASS,
                f"lib.books.author_id = {_ACCOUNT_SETTING}" + _BYPASS,
            ],
        )

    def test_identifiers_are_quoted(self) -> None:
        Base: typing.Any = _new_base()

        class User(Base):
            __tablename__ = "user"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class Order(Base):
            __tablename__ = "order"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            user_id = sqlalchemy.Column(
                "User Id", sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id")
            )
            user = orm.relationship(User)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("user", allow_bypass_rls=False),
                policy.Policy.from_relationship(
                    "user",
                    cmd=policy.Command.select,
                    condition_arg=_ACCOUNT_ID,
                    allow_bypass_rls=False,
                ),
            ]

        self.assertEqual(
            _exprs(Base, "order"),
            [
                'EXISTS (SELECT 1 FROM "user" WHERE "user".id = "order"."User Id")',
                f'"order"."User Id" = {_ACCOUNT_SETTING}',
            ],
        )

    def test_policy_options_are_applied(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship(
                    "author",
                    cmd=policy.Command.select,
                    name="Book Author",
                    policy_type=policy.PolicyType.restrictive,
                    roles=["app_user"],
                )
            ]
        )
        (resolved,) = policy.resolved_policies(Base.metadata)["books"]
        assert isinstance(resolved, policy.Policy)
        self.assertEqual(resolved.cmd, policy.Command.select)
        self.assertEqual(resolved.policy_type, policy.PolicyType.restrictive)
        self.assertEqual(resolved.roles, ("app_user",))
        self.assertRegex(resolved.name, r"^book author_[0-9a-z]{8}$")

    def test_default_names(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship("author"),
                policy.Policy.from_relationship(
                    "tags", cmd=policy.Command.select, condition_arg=_ACCOUNT_ID
                ),
            ]
        )
        names = [p.name for p in policy.resolved_policies(Base.metadata)["books"]]
        self.assertRegex(names[0], r"^permissive_author_all_[0-9a-z]{8}$")
        self.assertRegex(names[1], r"^permissive_tags_account_id_select_[0-9a-z]{8}$")

    def test_mixed_with_other_policies(self) -> None:
        external = policy.ExternalPolicy(name="legacy")
        (owner,) = _owner_policies("author_id")
        Base = _library([external, policy.Policy.from_relationship("author"), owner])
        resolved = policy.resolved_policies(Base.metadata)["books"]
        self.assertIs(resolved[0], external)
        self.assertIsInstance(resolved[1], policy.Policy)
        self.assertIs(resolved[2], owner)

    def test_mixin_policies_resolve_for_each_model(self) -> None:
        Base: typing.Any = _new_base()

        class Owner(Base):
            __tablename__ = "owners"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class OwnedMixin:
            owner_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("owners.id")
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("owner", allow_bypass_rls=False)
            ]

            @orm.declared_attr
            def owner(cls) -> orm.Mapped[Owner]:
                return orm.relationship(Owner)

        class Cat(OwnedMixin, Base):
            __tablename__ = "cats"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Dog(OwnedMixin, Base):
            __tablename__ = "dogs"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        self.assertIn(Cat.__tablename__, Base.metadata.tables)
        self.assertIn(Dog.__tablename__, Base.metadata.tables)
        for table in ("cats", "dogs"):
            self.assertEqual(
                _exprs(Base, table),
                [f"EXISTS (SELECT 1 FROM owners WHERE owners.id = {table}.owner_id)"],
            )


class TestRelationshipPolicyResolution(unittest.TestCase):
    def test_declaration_is_not_a_policy_until_resolved(self) -> None:
        declared = policy.Policy.from_relationship("author")
        self.assertIsInstance(declared, policy.RelationshipPolicy)
        Base = _library([declared])
        self.assertEqual(Base.metadata.info["rls_policies"]["books"], [declared])

        resolved = policy.resolved_policies(Base.metadata)

        self.assertIsInstance(resolved["books"][0], policy.Policy)
        self.assertIs(resolved, Base.metadata.info["rls_policies"])
        # Resolving again returns the same policies.
        self.assertIs(
            policy.resolved_policies(Base.metadata)["books"][0], resolved["books"][0]
        )

    def test_resolved_policies_without_relationship_policies(self) -> None:
        Base = _library(_owner_policies("author_id"))
        before = dict(Base.metadata.info["rls_policies"])
        self.assertEqual(policy.resolved_policies(Base.metadata), before)

    def test_changing_the_join_changes_the_name(self) -> None:
        def name(column: str) -> str:
            Base: typing.Any = _new_base()

            class Author(Base):
                __tablename__ = "authors"
                id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
                __rls_policies__ = _owner_policies()

            class Book(Base):
                __tablename__ = "books"
                id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
                author_id = sqlalchemy.Column(
                    column, sqlalchemy.Integer, sqlalchemy.ForeignKey(Author.id)
                )
                author = orm.relationship(Author)
                __rls_policies__: typing.ClassVar[_Policies] = [
                    policy.Policy.from_relationship("author")
                ]

            return policy.resolved_policies(Base.metadata)[Book.__tablename__][0].name

        self.assertEqual(name("author_id"), name("author_id"))
        self.assertNotEqual(name("author_id"), name("writer_id"))

    def test_roles_must_not_be_a_string(self) -> None:
        with self.assertRaisesRegex(TypeError, "sequence of role names"):
            policy.Policy.from_relationship("author", roles="app_user")

    def test_roles_must_not_be_empty(self) -> None:
        with self.assertRaisesRegex(ValueError, "roles must not be empty"):
            policy.Policy.from_relationship("author", roles=[])

    def test_unknown_relationship_raises(self) -> None:
        Base = _library([policy.Policy.from_relationship("writer")])
        with self.assertRaisesRegex(
            ValueError, r"Book\.writer: Book has no relationship named 'writer'"
        ):
            policy.resolved_policies(Base.metadata)

    def test_column_attribute_is_not_a_relationship(self) -> None:
        Base = _library([policy.Policy.from_relationship("author_id")])
        with self.assertRaisesRegex(ValueError, "no relationship named 'author_id'"):
            policy.resolved_policies(Base.metadata)

    def test_related_table_without_policies_raises(self) -> None:
        Base = _library([policy.Policy.from_relationship("author")], author_policies=[])
        with self.assertRaisesRegex(ValueError, r"\['authors'\] have no RLS policies"):
            policy.resolved_policies(Base.metadata)

    def test_association_table_without_policies_raises(self) -> None:
        for condition_arg in (None, _ACCOUNT_ID):
            with self.subTest(condition_arg=condition_arg):
                Base = _library(
                    [
                        policy.Policy.from_relationship(
                            "tags", condition_arg=condition_arg
                        )
                    ],
                    link_policies=[],
                )
                with self.assertRaisesRegex(
                    ValueError,
                    r"Book\.tags: the association table 'book_tags' has no RLS",
                ):
                    policy.resolved_policies(Base.metadata)

    def test_mapped_association_table_is_protected_by_its_model(self) -> None:
        Base: typing.Any = _new_base()

        class Member(Base):
            __tablename__ = "members"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Membership(Base):
            __tablename__ = "memberships"
            team_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("teams.id"), primary_key=True
            )
            member_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey(Member.id), primary_key=True
            )
            member = orm.relationship(Member)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship(
                    "member", cmd=policy.Command.select, condition_arg=_ACCOUNT_ID
                )
            ]

        class Team(Base):
            __tablename__ = "teams"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            members = orm.relationship(Member, secondary=Membership.__table__)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("members", condition_arg=_ACCOUNT_ID)
            ]

        self.assertEqual(_cmds(Base, Team.__tablename__), [policy.Command.all])
        self.assertEqual(_cmds(Base, "memberships"), [policy.Command.select])

    def test_condition_arg_does_not_need_related_policies(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("author", condition_arg=_ACCOUNT_ID)],
            author_policies=[],
        )
        self.assertEqual(len(_exprs(Base, "books")), 1)

    def test_duplicate_relationship_policies_raise(self) -> None:
        Base = _library([policy.Policy.from_relationship("author")] * 2)
        with self.assertRaisesRegex(ValueError, "Duplicate RLS policy names"):
            policy.resolved_policies(Base.metadata)

    def test_policies_in_a_cycle_raise(self) -> None:
        Base = _library(
            book_policies=[policy.Policy.from_relationship("author")],
            author_policies=[policy.Policy.from_relationship("books")],
        )
        with self.assertRaisesRegex(ValueError, "authors -> books -> authors"):
            policy.resolved_policies(Base.metadata)

    def test_write_only_policy_is_not_a_cycle(self) -> None:
        """Only SELECT policies apply to the rows a policy's subquery reads."""
        Base = _library(
            book_policies=[policy.Policy.from_relationship("author")],
            author_policies=[
                *_owner_policies(),
                policy.Policy.from_relationship("books", cmd=policy.Command.delete),
            ],
        )
        self.assertEqual(len(_exprs(Base, "authors")), 2)

    def test_self_referential_relationship_raises(self) -> None:
        Base: typing.Any = _new_base()

        class Node(Base):
            __tablename__ = "nodes"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            parent_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("nodes.id")
            )
            parent = orm.relationship("Node", remote_side=[id])
            __rls_policies__: typing.ClassVar[_Policies] = [
                *_owner_policies(),
                policy.Policy.from_relationship("parent"),
            ]

        self.assertIn(Node.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(ValueError, "self-referential"):
            policy.resolved_policies(Base.metadata)

    def test_self_referential_relationship_with_condition_arg(self) -> None:
        Base: typing.Any = _new_base()

        class Node(Base):
            __tablename__ = "nodes"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            parent_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("nodes.id")
            )
            parent = orm.relationship("Node", remote_side=[id])
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship(
                    "parent", condition_arg=_ACCOUNT_ID, allow_bypass_rls=False
                ),
            ]

        self.assertEqual(
            _exprs(Base, Node.__tablename__),
            [f"nodes.parent_id = {_ACCOUNT_SETTING}"],
        )

    def test_one_to_many_with_condition_arg_raises(self) -> None:
        Base = _library(
            book_policies=_owner_policies("author_id"),
            author_policies=[
                policy.Policy.from_relationship("books", condition_arg=_ACCOUNT_ID)
            ],
        )
        with self.assertRaisesRegex(ValueError, "not ONETOMANY"):
            policy.resolved_policies(Base.metadata)

    def test_composite_primary_key_with_condition_arg_raises(self) -> None:
        Base: typing.Any = _new_base()

        class Edition(Base):
            __tablename__ = "editions"
            isbn = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            number = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Copy(Base):
            __tablename__ = "copies"
            __table_args__ = (
                sqlalchemy.ForeignKeyConstraint(
                    ["isbn", "number"], ["editions.isbn", "editions.number"]
                ),
            )
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            isbn = sqlalchemy.Column(sqlalchemy.Integer)
            number = sqlalchemy.Column(sqlalchemy.Integer)
            edition = orm.relationship(Edition)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("edition", condition_arg=_ACCOUNT_ID)
            ]

        self.assertIn(Copy.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(ValueError, "composite primary key"):
            policy.resolved_policies(Base.metadata)

    def test_foreign_key_to_non_primary_key_with_condition_arg_raises(self) -> None:
        Base: typing.Any = _new_base()

        class Country(Base):
            __tablename__ = "countries"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            code = sqlalchemy.Column(sqlalchemy.String, unique=True)

        class City(Base):
            __tablename__ = "cities"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            country_code = sqlalchemy.Column(
                sqlalchemy.String, sqlalchemy.ForeignKey("countries.code")
            )
            country = orm.relationship(Country)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("country", condition_arg=_ACCOUNT_ID)
            ]

        self.assertIn(City.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(ValueError, "does not join on the primary key"):
            policy.resolved_policies(Base.metadata)

    def test_relationship_columns_on_parent_table_raise(self) -> None:
        """With joined-table inheritance the policy must be declared on the
        model whose table holds the foreign key."""
        Base: typing.Any = _new_base()

        class Owner(Base):
            __tablename__ = "owners"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class Document(Base):
            __tablename__ = "documents"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("owners.id")
            )
            owner = orm.relationship(Owner)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("owner")
            ]

        class Report(Document):
            __tablename__ = "reports"
            id = sqlalchemy.Column(
                sqlalchemy.Integer,
                sqlalchemy.ForeignKey("documents.id"),
                primary_key=True,
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("owner")
            ]

        self.assertIn(Report.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(
            ValueError, r"Report\.owner: .*not on the 'reports' table"
        ):
            policy.resolved_policies(Base.metadata)

    def test_single_table_inheritance_target_raises(self) -> None:
        """The discriminator criterion of a single table inheritance
        subclass is not part of the join condition, so the policy would
        also match rows of the other classes."""
        Base: typing.Any = _new_base()

        class Person(Base):
            __tablename__ = "people"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            kind = sqlalchemy.Column(sqlalchemy.String)
            __mapper_args__: typing.ClassVar[dict[str, typing.Any]] = {
                "polymorphic_on": kind,
                "polymorphic_identity": "person",
            }
            __rls_policies__ = _owner_policies()

        class Admin(Person):
            __mapper_args__: typing.ClassVar[dict[str, typing.Any]] = {
                "polymorphic_identity": "admin"
            }

        class Ticket(Base):
            __tablename__ = "tickets"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            admin_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("people.id")
            )
            admin = orm.relationship(Admin)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("admin")
            ]

        self.assertIn(Ticket.__tablename__, Base.metadata.tables)
        for condition_arg in (None, _ACCOUNT_ID):
            with self.subTest(condition_arg=condition_arg):
                Ticket.__rls_policies__[0] = policy.Policy.from_relationship(
                    "admin", condition_arg=condition_arg
                )
                with self.assertRaisesRegex(
                    ValueError, r"Ticket\.admin: .*single table inheritance"
                ):
                    policy.resolved_policies(Base.metadata)

    def _book_with_enabled_author(
        self, condition_arg: policy.ConditionArg | None
    ) -> typing.Any:
        Base: typing.Any = _new_base()

        class Author(Base):
            __tablename__ = "authors"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class Book(Base):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            enabled = sqlalchemy.Column(sqlalchemy.Boolean)
            author_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("authors.id")
            )
            author = orm.relationship(
                Author,
                primaryjoin=lambda: sqlalchemy.and_(
                    Book.author_id == Author.id, Book.enabled == sql.true()
                ),
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship(
                    "author", condition_arg=condition_arg, allow_bypass_rls=False
                )
            ]

        return Base

    def test_extra_join_criteria_are_kept(self) -> None:
        Base = self._book_with_enabled_author(condition_arg=None)
        self.assertEqual(
            _exprs(Base, "books"),
            [
                (
                    "EXISTS (SELECT 1 FROM authors WHERE "
                    "books.author_id = authors.id AND books.enabled = true)"
                )
            ],
        )

    def test_extra_join_criteria_with_condition_arg_raise(self) -> None:
        Base = self._book_with_enabled_author(condition_arg=_ACCOUNT_ID)
        with self.assertRaisesRegex(ValueError, r"Book\.author: .*other criteria"):
            policy.resolved_policies(Base.metadata)

    def test_extra_secondary_join_criteria_with_condition_arg_raise(self) -> None:
        Base: typing.Any = _new_base()
        memberships = sqlalchemy.Table(
            "memberships",
            Base.metadata,
            sqlalchemy.Column("team_id", sqlalchemy.ForeignKey("teams.id")),
            sqlalchemy.Column("member_id", sqlalchemy.ForeignKey("members.id")),
            sqlalchemy.Column("active", sqlalchemy.Boolean),
        )
        register.table_policies(memberships, [_owner_policy("member_id")])

        class Member(Base):
            __tablename__ = "members"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Team(Base):
            __tablename__ = "teams"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            members = orm.relationship(
                Member,
                secondary=memberships,
                secondaryjoin=lambda: sqlalchemy.and_(
                    Member.id == memberships.c.member_id,
                    memberships.c.active == sql.true(),
                ),
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("members", condition_arg=_ACCOUNT_ID)
            ]

        self.assertIn(Team.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(ValueError, r"Team\.members: .*other criteria"):
            policy.resolved_policies(Base.metadata)

    def test_cycle_check_visits_shared_tables_once(self) -> None:
        """Each layer's two tables both read both tables of the next layer,
        so there are 2**layers paths through the graph."""
        Base: typing.Any = _new_base()
        layers = 40
        # The class registry only holds weak references.
        models = []
        for layer in reversed(range(layers)):
            for name in ("a", "b"):
                attrs: dict[str, typing.Any] = {
                    "__tablename__": f"{name}{layer}",
                    "id": sqlalchemy.Column(sqlalchemy.Integer, primary_key=True),
                }
                if layer == layers - 1:
                    attrs["__rls_policies__"] = _owner_policies()
                else:
                    attrs["__rls_policies__"] = []
                    for target in ("a", "b"):
                        attrs[f"{target}_id"] = sqlalchemy.Column(
                            sqlalchemy.Integer,
                            sqlalchemy.ForeignKey(f"{target}{layer + 1}.id"),
                        )
                        attrs[target] = orm.relationship(f"{target.upper()}{layer + 1}")
                        attrs["__rls_policies__"].append(
                            policy.Policy.from_relationship(target)
                        )
                models.append(type(f"{name.upper()}{layer}", (Base,), attrs))

        self.assertEqual(len(models), 2 * layers)
        self.assertEqual(len(_exprs(Base, "a0")), 2)

    def test_joined_table_inheritance_target(self) -> None:
        """Without condition_arg the subclass's table is part of the EXISTS;
        with it, only the foreign key would be compared, which cannot check
        that the related row is of the subclass."""
        Base: typing.Any = _new_base()

        class Person(Base):
            __tablename__ = "people"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class Admin(Person):
            __tablename__ = "admins"
            id = sqlalchemy.Column(
                sqlalchemy.Integer,
                sqlalchemy.ForeignKey("people.id"),
                primary_key=True,
            )

        class Ticket(Base):
            __tablename__ = "tickets"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            admin_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("people.id")
            )
            admin = orm.relationship(Admin)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("admin", allow_bypass_rls=False)
            ]

        self.assertIn(Admin.__tablename__, Base.metadata.tables)
        self.assertEqual(
            _exprs(Base, "tickets"),
            [
                (
                    "EXISTS (SELECT 1 FROM people JOIN admins ON people.id = "
                    "admins.id WHERE people.id = tickets.admin_id)"
                )
            ],
        )

    def test_joined_table_inheritance_target_with_condition_arg_raises(
        self,
    ) -> None:
        Base: typing.Any = _new_base()

        class Person(Base):
            __tablename__ = "people"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Admin(Person):
            __tablename__ = "admins"
            id = sqlalchemy.Column(
                sqlalchemy.Integer,
                sqlalchemy.ForeignKey("people.id"),
                primary_key=True,
            )

        class Ticket(Base):
            __tablename__ = "tickets"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            admin_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("people.id")
            )
            admin = orm.relationship(Admin)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("admin", condition_arg=_ACCOUNT_ID)
            ]

        self.assertIn(Admin.__tablename__, Base.metadata.tables)
        self.assertIn(Ticket.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(
            ValueError, r"Ticket\.admin: .*Admin inherits from Person"
        ):
            policy.resolved_policies(Base.metadata)

    def test_target_columns_in_primary_join_with_condition_arg_raise(
        self,
    ) -> None:
        """Without the secondary join, a related-table column in the primary
        join would not be correlated with the linked row."""
        Base: typing.Any = _new_base()
        memberships = sqlalchemy.Table(
            "memberships",
            Base.metadata,
            sqlalchemy.Column("team_id", sqlalchemy.ForeignKey("teams.id")),
            sqlalchemy.Column("member_id", sqlalchemy.ForeignKey("members.id")),
        )
        register.table_policies(memberships, [_owner_policy("member_id")])

        class Member(Base):
            __tablename__ = "members"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            active = sqlalchemy.Column(sqlalchemy.Boolean)

        class Team(Base):
            __tablename__ = "teams"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            members = orm.relationship(
                Member,
                secondary=memberships,
                primaryjoin=lambda: sqlalchemy.and_(
                    Team.id == memberships.c.team_id, Member.active == sql.true()
                ),
                viewonly=True,
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("members", condition_arg=_ACCOUNT_ID)
            ]

        self.assertIn(Team.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(
            ValueError, r"Team\.members: .*column members\.active"
        ):
            policy.resolved_policies(Base.metadata)


_TAG_VISIBLE = "(EXISTS (SELECT 1 FROM tags WHERE tags.id = book_tags.tag_id))"
_BOOKS_VISIBLE = policy.RowVisibleFunction("books", "id", "INTEGER").name
_BOTH_VISIBLE = f"{_BOOKS_VISIBLE}(book_tags.book_id) AND " + _TAG_VISIBLE


class TestLinkPolicies(unittest.TestCase):
    def test_generates_association_table_policies(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("tags", link_policies=True)],
            link_policies=[],
        )
        resolved = typing.cast(
            list[policy.Policy], policy.resolved_policies(Base.metadata)["book_tags"]
        )
        self.assertEqual(
            [(p.cmd, " ".join(p.expr.split())) for p in resolved],
            [
                (policy.Command.select, _TAG_VISIBLE + _BYPASS),
                (policy.Command.insert, _BOTH_VISIBLE + _BYPASS),
                (policy.Command.update, _BOTH_VISIBLE + _BYPASS),
                (policy.Command.delete, _BOTH_VISIBLE + _BYPASS),
            ],
        )
        self.assertTrue(
            all(
                p.name.startswith(f"link_books_tags_{p.cmd.value.lower()}_")
                for p in resolved
            )
        )
        self.assertEqual(
            policy.row_visible_functions(Base.metadata),
            [policy.RowVisibleFunction("books", "id", "INTEGER")],
        )
        self.assertEqual(
            Base.metadata.info["rls_modes"]["book_tags"],
            policy.RlsMode.enable_and_force,
        )
        # The relationship policy itself is unchanged.
        self.assertEqual(len(_exprs(Base, "books")), 1)

    def test_options_apply_to_link_policies(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship(
                    "tags",
                    link_policies=True,
                    allow_bypass_rls=False,
                    roles=["app"],
                )
            ],
            link_policies=[],
        )
        resolved = typing.cast(
            list[policy.Policy], policy.resolved_policies(Base.metadata)["book_tags"]
        )
        self.assertEqual(" ".join(resolved[0].expr.split()), _TAG_VISIBLE[1:-1])
        self.assertTrue(all(p.roles == ("app",) for p in resolved))

    def test_schema_qualified_tables(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("tags", link_policies=True)],
            link_policies=[],
            schema="lib",
        )
        insert = typing.cast(
            policy.Policy, policy.resolved_policies(Base.metadata)["lib.book_tags"][1]
        )
        self.assertIn(f"lib.{_BOOKS_VISIBLE}(lib.book_tags.book_id)", insert.expr)
        (function,) = policy.row_visible_functions(Base.metadata)
        self.assertEqual(function.signature, f"lib.{_BOOKS_VISIBLE}(INTEGER)")
        self.assertIn(
            "FROM lib.books WHERE lib.books.id = $1",
            function.body("lib"),
        )

    def test_mixed_case_schema_is_quoted(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("tags", link_policies=True)],
            link_policies=[],
            schema="MixedSchema",
        )
        insert = typing.cast(
            policy.Policy,
            policy.resolved_policies(Base.metadata)["MixedSchema.book_tags"][1],
        )
        self.assertIn(f'"MixedSchema".{_BOOKS_VISIBLE}(', insert.expr)

    def test_resolving_again_after_registering_again(self) -> None:
        Base = _library(
            [policy.Policy.from_relationship("tags", link_policies=True)],
            link_policies=[],
        )
        first = policy.resolved_policies(Base.metadata)["book_tags"]
        register.base_wrapper(Base)
        self.assertEqual(
            [p.name for p in policy.resolved_policies(Base.metadata)["book_tags"]],
            [p.name for p in first],
        )

    def test_function_names(self) -> None:
        self.assertTrue(
            policy.RowVisibleFunction("books", "id", "INTEGER").name.startswith(
                "rls_visible_books_id_"
            )
        )
        # Lowercase (SQLAlchemy does not quote function names) and at most
        # 63 bytes, with a hash to keep them distinct.
        for table, column in (("Books", "id"), ("b" * 70, "id"), ("b" * 70, "id2")):
            with self.subTest(table=table, column=column):
                name = policy.RowVisibleFunction(table, column, "INTEGER").name
                self.assertEqual(name, name.lower())
                self.assertLessEqual(len(name), 63)
        self.assertNotEqual(
            policy.RowVisibleFunction("Books", "id", "INTEGER").name,
            policy.RowVisibleFunction("books", "id", "INTEGER").name,
        )
        self.assertNotEqual(
            policy.RowVisibleFunction("b" * 70, "id", "INTEGER").name,
            policy.RowVisibleFunction("b" * 70, "id2", "INTEGER").name,
        )
        self.assertNotEqual(
            policy.RowVisibleFunction("accounts_users", "id", "INTEGER").name,
            policy.RowVisibleFunction("accounts", "users_id", "INTEGER").name,
        )

    def test_function_marker_round_trips(self) -> None:
        function = policy.RowVisibleFunction("books", "id", "UUID", schemaname="lib")
        self.assertEqual(
            policy.RowVisibleFunction.from_body(function.body('"lib"')), function
        )
        self.assertIsNone(policy.RowVisibleFunction.from_body("BEGIN RETURN true; END"))

    def test_added_to_declared_table_policies(self) -> None:
        Base = _library([policy.Policy.from_relationship("tags", link_policies=True)])
        self.assertEqual(
            _cmds(Base, "book_tags"),
            [
                policy.Command.all,
                policy.Command.select,
                policy.Command.insert,
                policy.Command.update,
                policy.Command.delete,
            ],
        )

    def test_not_many_to_many_raises(self) -> None:
        Base = _library([policy.Policy.from_relationship("author", link_policies=True)])
        with self.assertRaisesRegex(ValueError, r"Book\.author: .*many-to-many"):
            policy.resolved_policies(Base.metadata)

    def test_condition_arg_raises(self) -> None:
        Base = _library(
            [
                policy.Policy.from_relationship(
                    "tags", condition_arg=_ACCOUNT_ID, link_policies=True
                )
            ],
            link_policies=[],
        )
        with self.assertRaisesRegex(ValueError, r"Book\.tags: .*condition_arg"):
            policy.resolved_policies(Base.metadata)

    def test_link_select_policy_is_part_of_the_cycle_check(self) -> None:
        """The links' SELECT policy reads the tags, so tags must not follow
        the books."""
        Base: typing.Any = _new_base()
        book_tags = sqlalchemy.Table(
            "book_tags",
            Base.metadata,
            sqlalchemy.Column("book_id", sqlalchemy.ForeignKey("books.id")),
            sqlalchemy.Column("tag_id", sqlalchemy.ForeignKey("tags.id")),
        )

        class Book(Base):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            tags = orm.relationship("Tag", secondary=book_tags)
            __rls_policies__: typing.ClassVar[_Policies] = [
                *_owner_policies("owner_id"),
                policy.Policy.from_relationship("tags", link_policies=True),
            ]

        class Tag(Base):
            __tablename__ = "tags"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            primary_book_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("books.id")
            )
            primary_book = orm.relationship(Book)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("primary_book")
            ]

        self.assertIn(Tag.__tablename__, Base.metadata.tables)
        with self.assertRaisesRegex(ValueError, "cycle"):
            policy.resolved_policies(Base.metadata)


class _Context(pydantic.BaseModel):
    account_id: int | None = None


class TestTablePolicies(unittest.TestCase):
    def _table(self, base: typing.Any) -> sqlalchemy.Table:
        return sqlalchemy.Table(
            "links",
            base.metadata,
            sqlalchemy.Column("left_id", sqlalchemy.Integer),
            sqlalchemy.Column("right_id", sqlalchemy.Integer),
        )

    def test_registers_policies_and_mode(self) -> None:
        Base: typing.Any = _new_base()
        table = self._table(Base)
        external = policy.ExternalPolicy(name="legacy")
        owner = _owner_policy("left_id")
        register.table_policies(table, [owner, external], rls_mode="ENABLE")
        self.assertEqual(
            policy.resolved_policies(Base.metadata), {"links": [owner, external]}
        )
        self.assertEqual(
            Base.metadata.info["rls_modes"], {"links": policy.RlsMode.enable}
        )

    def test_default_mode_and_schema(self) -> None:
        Base: typing.Any = _new_base()
        table = sqlalchemy.Table(
            "links",
            Base.metadata,
            sqlalchemy.Column("left_id", sqlalchemy.Integer),
            schema="lib",
        )
        register.table_policies(table, [_owner_policy("left_id")])
        self.assertEqual(
            Base.metadata.info["rls_modes"],
            {"lib.links": policy.RlsMode.enable_and_force},
        )

    def test_requires_registered_metadata(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        with self.assertRaisesRegex(ValueError, "not registered for RLS"):
            register.table_policies(self._table(Base), [_owner_policy("left_id")])

    def test_rejects_relationship_policies(self) -> None:
        Base: typing.Any = _new_base()
        with self.assertRaisesRegex(TypeError, "not RelationshipPolicy"):
            register.table_policies(
                self._table(Base),
                [policy.Policy.from_relationship("left")],  # type: ignore[list-item]
            )

    def test_rejects_duplicate_names(self) -> None:
        Base: typing.Any = _new_base()
        with self.assertRaisesRegex(ValueError, "Duplicate RLS policy names"):
            register.table_policies(self._table(Base), [_owner_policy("left_id")] * 2)

    def test_rejects_second_declaration(self) -> None:
        Base: typing.Any = _new_base()
        table = self._table(Base)
        register.table_policies(table, [_owner_policy("left_id")])
        with self.assertRaisesRegex(ValueError, "already has RLS policies"):
            register.table_policies(table, [_owner_policy("right_id")])

    def test_rejects_invalid_mode(self) -> None:
        Base: typing.Any = _new_base()
        table = self._table(Base)
        with self.assertRaises(ValueError):
            register.table_policies(table, [_owner_policy("left_id")], rls_mode="NOPE")
        self.assertEqual(Base.metadata.info["rls_policies"], {})

    def test_validates_context_fields(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        class Other(pydantic.BaseModel):
            tenant_id: int

        register.base_wrapper(Base, context_model=Other)
        with self.assertRaisesRegex(ValueError, r"reads \['account_id'\]"):
            register.table_policies(self._table(Base), [_owner_policy("left_id")])

    def test_context_model_given_later_checks_table_policies(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        class Other(pydantic.BaseModel):
            tenant_id: int

        register.base_wrapper(Base)
        register.table_policies(self._table(Base), [_owner_policy("left_id")])
        with self.assertRaisesRegex(ValueError, r"reads \['account_id'\]"):
            register.base_wrapper(Base, context_model=Other)


class TestRelationshipPolicyContextValidation(unittest.TestCase):
    def _models(self, base: typing.Any, comparator_name: str) -> None:
        class Author(base):
            __tablename__ = "authors"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

        class Book(base):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            author_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("authors.id")
            )
            author = orm.relationship(Author)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship(
                    "author",
                    condition_arg=policy.ConditionArg(
                        comparator_name=comparator_name, type=sqlalchemy.Integer
                    ),
                )
            ]

    def test_matching_context_field(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base, context_model=_Context)
        self._models(Base, "account_id")
        register.validate_context(Base, _Context)

    def test_comparator_typo_raises_when_model_is_defined(self) -> None:
        class Base(orm.DeclarativeBase):
            pass

        register.base_wrapper(Base, context_model=_Context)
        with self.assertRaisesRegex(
            ValueError, r"for relationship 'author' .* reads \['acount_id'\]"
        ):
            self._models(Base, "acount_id")

    def test_validate_context_checks_unresolved_policies(self) -> None:
        Base: typing.Any = _new_base()
        self._models(Base, "acount_id")
        with self.assertRaisesRegex(ValueError, "acount_id"):
            register.validate_context(Base, _Context)


class Base(orm.DeclarativeBase):
    pass


register.base_wrapper(Base, context_model=_Context)

article_tags = sqlalchemy.Table(
    "article_tags",
    Base.metadata,
    sqlalchemy.Column("article_id", sqlalchemy.ForeignKey("articles.id")),
    sqlalchemy.Column("tag_id", sqlalchemy.ForeignKey("tags.id")),
)

shelf_owners = sqlalchemy.Table(
    "shelf_owners",
    Base.metadata,
    sqlalchemy.Column("shelf_id", sqlalchemy.ForeignKey("shelves.id")),
    sqlalchemy.Column("author_id", sqlalchemy.ForeignKey("authors.id")),
)


class Author(Base):
    """Visible to the account with the same id."""

    __tablename__ = "authors"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    __rls_policies__ = _owner_policies()


class Book(Base):
    """Many-to-one: visible when its author is."""

    __tablename__ = "books"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    author_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.ForeignKey("authors.id")
    )
    author: orm.Mapped[Author | None] = orm.relationship()
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("author")
    ]


class Chapter(Base):
    """Many-to-one through another relationship policy (chapter -> book ->
    author)."""

    __tablename__ = "chapters"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    book_id: orm.Mapped[int] = orm.mapped_column(sqlalchemy.ForeignKey("books.id"))
    book: orm.Mapped[Book] = orm.relationship()
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("book")
    ]


class Review(Base):
    """Many-to-one compared with the context: visible to its reviewer."""

    __tablename__ = "reviews"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    reviewer_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("authors.id")
    )
    reviewer: orm.Mapped[Author] = orm.relationship()
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("reviewer", condition_arg=_ACCOUNT_ID)
    ]


class Tag(Base):
    __tablename__ = "tags"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    owner_id: orm.Mapped[int] = orm.mapped_column()
    __rls_policies__ = _owner_policies("owner_id")


class Article(Base):
    """Many-to-many: visible when one of its tags is."""

    __tablename__ = "articles"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    tags: orm.Mapped[list[Tag]] = orm.relationship(secondary=article_tags)
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("tags")
    ]


class Shelf(Base):
    """Many-to-many compared with the context: visible to its owners."""

    __tablename__ = "shelves"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    owners: orm.Mapped[list[Author]] = orm.relationship(secondary=shelf_owners)
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("owners", condition_arg=_ACCOUNT_ID),
        # A new shelf has no owners yet, so who may insert one is declared
        # separately: here, anyone.
        policy.Policy.from_sqla(
            expr=lambda: sql.true(), condition_args=[], cmd=policy.Command.insert
        ),
    ]


project_tags = sqlalchemy.Table(
    "project_tags",
    Base.metadata,
    sqlalchemy.Column(
        "project_id", sqlalchemy.ForeignKey("projects.id"), primary_key=True
    ),
    sqlalchemy.Column("tag_id", sqlalchemy.ForeignKey("tags.id"), primary_key=True),
)


class Project(Base):
    """Many-to-many with generated link policies: visible when one of its
    tags is, and linked to a tag by sessions that can see both."""

    __tablename__ = "projects"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    tags: orm.Mapped[list[Tag]] = orm.relationship(secondary=project_tags)
    __rls_policies__: typing.ClassVar[_Policies] = [
        policy.Policy.from_relationship("tags", link_policies=True)
    ]


def _bypass_only(cmd: policy.Command) -> policy.Policy:
    """Nobody passes the expression, so only bypass_rls() sessions do."""
    return policy.Policy.from_sqla(
        expr=lambda: sql.false(), condition_args=[], cmd=cmd, name="bypass_only"
    )


# The links decide who can access articles and shelves, so the association
# tables are protected too.  Sessions can read the links to their own tags and
# to shelves they own, and only change links with bypass_rls().
register.table_policies(
    article_tags,
    [
        policy.Policy.from_sqla(
            expr=lambda: sqlalchemy.exists().where(Tag.id == sql.column("tag_id")),
            condition_args=[],
            cmd=policy.Command.select,
        ),
        _bypass_only(policy.Command.insert),
        _bypass_only(policy.Command.delete),
    ],
)
register.table_policies(
    shelf_owners,
    [
        _owner_policy("author_id", policy.Command.select),
        _bypass_only(policy.Command.insert),
        _bypass_only(policy.Command.delete),
    ],
)

_ROLE = "relationship_user"
_PROJECTS_VISIBLE = policy.RowVisibleFunction("projects", "id", "INTEGER").name
_RELATIONSHIP_TABLES = (
    "books",
    "chapters",
    "reviews",
    "articles",
    "shelves",
    "projects",
)
_FUNCTIONS = "<functions>"


class RelationshipPolicyEndToEndTests(unittest.TestCase):
    postgresql: testing.postgresql.Postgresql
    admin_engine: sqlalchemy.engine.Engine
    engine: sqlalchemy.engine.Engine
    ops_before: dict[str, list]
    ops_after: dict[str, list]

    @classmethod
    def _autogenerate_ops(cls) -> dict[str, list]:
        with cls.admin_engine.connect() as connection:
            context = migration.MigrationContext.configure(
                connection, opts={"target_metadata": Base.metadata}
            )
            script = autogenerate.produce_migrations(context, Base.metadata)
        assert script.upgrade_ops is not None
        ops: dict[str, list] = {
            table_ops.table_name: list(table_ops.ops)
            for table_ops in script.upgrade_ops.ops
            if isinstance(table_ops, alembic_ops_module.ModifyTableOps)
        }
        functions = [
            op
            for op in script.upgrade_ops.ops
            if isinstance(op, alembic_ops.CreateRowVisibleFunctionOp)
        ]
        if functions:
            ops[_FUNCTIONS] = functions
        return ops

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgresql = testing.postgresql.Postgresql(
            postgres_args="-h 127.0.0.1 -F -c logging_collector=off"
        )
        url = sqlalchemy.engine.make_url(cls.postgresql.url()).set(
            drivername="postgresql+psycopg"
        )
        cls.admin_engine = sqlalchemy.create_engine(url)
        Base.metadata.create_all(cls.admin_engine)
        cls.ops_before = cls._autogenerate_ops()
        with cls.admin_engine.begin() as connection:
            create_policies.create_policies_no_commit(Base, connection)
            connection.execute(sqlalchemy.insert(Author), [{"id": 1}, {"id": 2}])
            connection.execute(
                sqlalchemy.insert(Book),
                [
                    {"id": 1, "author_id": 1},
                    {"id": 2, "author_id": 2},
                    {"id": 3, "author_id": None},
                ],
            )
            connection.execute(
                sqlalchemy.insert(Chapter),
                [{"id": 1, "book_id": 1}, {"id": 2, "book_id": 2}],
            )
            connection.execute(
                sqlalchemy.insert(Review),
                [{"id": 1, "reviewer_id": 1}, {"id": 2, "reviewer_id": 2}],
            )
            connection.execute(
                sqlalchemy.insert(Tag),
                [
                    {"id": 1, "owner_id": 1},
                    {"id": 2, "owner_id": 2},
                    {"id": 3, "owner_id": 1},
                ],
            )
            connection.execute(
                sqlalchemy.insert(Project), [{"id": i} for i in range(1, 4)]
            )
            # Project 3 has no tags.
            connection.execute(
                sqlalchemy.insert(project_tags),
                [{"project_id": 1, "tag_id": 1}, {"project_id": 2, "tag_id": 2}],
            )
            connection.execute(
                sqlalchemy.insert(Article), [{"id": i} for i in range(1, 5)]
            )
            # Article 3 has both tags and article 4 has none.
            connection.execute(
                sqlalchemy.insert(article_tags),
                [
                    {"article_id": 1, "tag_id": 1},
                    {"article_id": 2, "tag_id": 2},
                    {"article_id": 3, "tag_id": 1},
                    {"article_id": 3, "tag_id": 2},
                ],
            )
            connection.execute(
                sqlalchemy.insert(Shelf), [{"id": i} for i in range(1, 5)]
            )
            # Shelf 3 has both owners and shelf 4 has none.
            connection.execute(
                sqlalchemy.insert(shelf_owners),
                [
                    {"shelf_id": 1, "author_id": 1},
                    {"shelf_id": 2, "author_id": 2},
                    {"shelf_id": 3, "author_id": 1},
                    {"shelf_id": 3, "author_id": 2},
                ],
            )
            connection.execute(
                sqlalchemy.text(
                    f"CREATE ROLE {_ROLE} LOGIN PASSWORD '{_ROLE}';"
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                    f"IN SCHEMA public TO {_ROLE};"
                )
            )
        cls.ops_after = cls._autogenerate_ops()
        cls.engine = sqlalchemy.create_engine(url.set(username=_ROLE, password=_ROLE))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.dispose()
        cls.admin_engine.dispose()
        cls.postgresql.stop()

    def _session(self, account_id: int | None) -> session.RlsSession:
        return session.RlsSession(
            context=_Context(account_id=account_id), bind=self.engine
        )

    def _visible(
        self, model: type[Base], account_id: int | None, bypass: bool = False
    ) -> list[int]:
        statement = sqlalchemy.select(model.id).order_by(model.id)  # type: ignore[attr-defined]
        with self._session(account_id) as sess:
            if bypass:
                with sess.bypass_rls():
                    return list(sess.execute(statement).scalars())
            return list(sess.execute(statement).scalars())

    def test_many_to_one(self) -> None:
        self.assertEqual(self._visible(Book, 1), [1])
        self.assertEqual(self._visible(Book, 2), [2])

    def test_many_to_one_chain(self) -> None:
        self.assertEqual(self._visible(Chapter, 1), [1])
        self.assertEqual(self._visible(Chapter, 2), [2])

    def test_many_to_one_with_condition_arg(self) -> None:
        self.assertEqual(self._visible(Review, 1), [1])
        self.assertEqual(self._visible(Review, 2), [2])

    def test_many_to_many(self) -> None:
        self.assertEqual(self._visible(Article, 1), [1, 3])
        self.assertEqual(self._visible(Article, 2), [2, 3])

    def test_many_to_many_with_condition_arg(self) -> None:
        self.assertEqual(self._visible(Shelf, 1), [1, 3])
        self.assertEqual(self._visible(Shelf, 2), [2, 3])

    def test_unknown_or_missing_account_sees_nothing(self) -> None:
        for model in (Book, Chapter, Review, Article, Shelf):
            for account_id in (3, None):
                with self.subTest(model=model.__name__, account_id=account_id):
                    self.assertEqual(self._visible(model, account_id), [])

    def test_bypass_rls_also_shows_unrelated_rows(self) -> None:
        self.assertEqual(self._visible(Book, None, bypass=True), [1, 2, 3])
        self.assertEqual(self._visible(Chapter, None, bypass=True), [1, 2])
        self.assertEqual(self._visible(Review, None, bypass=True), [1, 2])
        self.assertEqual(self._visible(Article, None, bypass=True), [1, 2, 3, 4])
        self.assertEqual(self._visible(Shelf, None, bypass=True), [1, 2, 3, 4])

    def test_orm_relationship_loads_under_policy(self) -> None:
        with self._session(1) as sess:
            book = sess.execute(sqlalchemy.select(Book)).scalar_one()
            assert book.author is not None
            self.assertEqual(book.author.id, 1)

    def test_writes_are_checked_against_the_relationship(self) -> None:
        with self._session(1) as sess:
            sess.add(Book(id=10, author_id=1))
            sess.flush()
            sess.rollback()
        for values in ({"author_id": 2}, {"author_id": None}):
            with self.subTest(values), self._session(1) as sess:
                sess.add(Book(id=10, **values))
                with self.assertRaisesRegex(
                    exc.DBAPIError, "row-level security policy"
                ):
                    sess.flush()
        with self._session(1) as sess:
            # Rows of another account are neither updated nor deleted.
            updated = sess.execute(sqlalchemy.update(Book).values(author_id=1))
            self.assertEqual(updated.rowcount, 1)  # type: ignore[attr-defined]
            deleted = sess.execute(sqlalchemy.delete(Chapter))
            self.assertEqual(deleted.rowcount, 1)  # type: ignore[attr-defined]
            sess.rollback()

    def test_linking_a_row_does_not_grant_access_to_it(self) -> None:
        """Account 1 must not be able to reach another account's row by
        linking it to something of its own."""
        for model, table, values in (
            (Article, article_tags, {"article_id": 2, "tag_id": 1}),
            (Shelf, shelf_owners, {"shelf_id": 2, "author_id": 1}),
        ):
            with self.subTest(model=model.__name__), self._session(1) as sess:
                with self.assertRaisesRegex(
                    exc.DBAPIError, "row-level security policy"
                ):
                    sess.execute(sqlalchemy.insert(table).values(values))
                sess.rollback()
                self.assertEqual(self._visible(model, 1), [1, 3])

    def test_links_of_other_accounts_cannot_be_removed(self) -> None:
        for table in (article_tags, shelf_owners):
            with self.subTest(table=table.name), self._session(1) as sess:
                deleted = sess.execute(sqlalchemy.delete(table))
                self.assertEqual(deleted.rowcount, 0)  # type: ignore[attr-defined]
                sess.rollback()

    def test_new_linked_row_does_not_pass_the_relationship_policy(self) -> None:
        """A new row has no links yet, so without another INSERT policy only
        bypass_rls() can insert it."""
        with self._session(1) as sess:
            with self.assertRaisesRegex(exc.DBAPIError, "row-level security policy"):
                sess.execute(sqlalchemy.insert(Article).values(id=50))
            sess.rollback()
            with sess.bypass_rls():
                sess.add(Article(id=50, tags=[sess.get_one(Tag, 1)]))
                sess.flush()
            visible = sess.execute(sqlalchemy.select(Article.id).order_by(Article.id))
            self.assertEqual(list(visible.scalars()), [1, 3, 50])
            sess.rollback()

    def test_separate_insert_policy_allows_new_linked_rows(self) -> None:
        with self._session(1) as sess:
            sess.execute(sqlalchemy.insert(Shelf).values(id=50))
            # Not visible until it is linked, which also means the insert
            # cannot use RETURNING.
            self.assertIsNone(sess.get(Shelf, 50))
            with self.assertRaisesRegex(exc.DBAPIError, "row-level security policy"):
                sess.execute(sqlalchemy.insert(Shelf).values(id=51).returning(Shelf.id))
            sess.rollback()

    def test_inaccessible_linked_rows_are_not_deleted(self) -> None:
        with self._session(1) as sess:
            for model in (Article, Shelf):
                deleted = sess.execute(
                    sqlalchemy.delete(model).where(model.id.in_([2, 4]))  # type: ignore[attr-defined]
                )
                self.assertEqual(deleted.rowcount, 0)  # type: ignore[attr-defined]
            sess.rollback()

    def test_autogenerate_creates_relationship_policies(self) -> None:
        resolved = policy.resolved_policies(Base.metadata)
        for table in _RELATIONSHIP_TABLES:
            with self.subTest(table):
                enable, *creates = self.ops_before[table]
                self.assertIsInstance(enable, alembic_ops.EnableRlsOp)
                expected = typing.cast(list[policy.Policy], resolved[table])
                self.assertEqual(
                    [(op.policy_name, op.cmd, op.expr) for op in creates],
                    [(p.name, p.cmd.value, p.expr) for p in expected],
                )

    def test_autogenerate_protects_association_tables(self) -> None:
        for table, policies in (
            ("article_tags", 3),
            ("shelf_owners", 3),
            ("project_tags", 4),
        ):
            with self.subTest(table):
                self.assertEqual(
                    [type(op) for op in self.ops_before[table]],
                    [alembic_ops.EnableRlsOp] + [alembic_ops.CreatePolicyOp] * policies,
                )

    def test_autogenerate_creates_the_helper_function(self) -> None:
        (op,) = self.ops_before[_FUNCTIONS]
        self.assertFalse(op.replaces)
        self.assertIsInstance(op.reverse(), alembic_ops.DropRowVisibleFunctionOp)
        rendered = autogenerate.render_python_code(
            alembic_ops_module.UpgradeOps(ops=[op, op.reverse()])
        )
        self.assertIn(
            "typing.cast(alembic_ops.RLSOp, op).create_rls_row_visible_function("
            "'projects', 'id', 'INTEGER')",
            rendered,
        )
        self.assertIn(
            "typing.cast(alembic_ops.RLSOp, op).drop_rls_row_visible_function("
            "'projects', 'id', 'INTEGER')",
            rendered,
        )

    def _link(
        self, account_id: int, project_id: int, tag_id: int, bypass: bool = False
    ) -> None:
        with self._session(account_id) as sess:
            statement = sqlalchemy.insert(project_tags).values(
                project_id=project_id, tag_id=tag_id
            )
            if bypass:
                with sess.bypass_rls():
                    sess.execute(statement)
            else:
                sess.execute(statement)
            sess.rollback()

    def test_link_policies_allow_linking_rows_the_session_can_see(self) -> None:
        self._link(1, project_id=1, tag_id=3)

    def test_link_policies_reject_links_to_rows_the_session_cannot_see(
        self,
    ) -> None:
        for project_id, tag_id in (
            (2, 3),  # another account's project
            (1, 2),  # another account's tag
            (3, 3),  # a project without tags is not visible yet
        ):
            with (
                self.subTest(project_id=project_id, tag_id=tag_id),
                self.assertRaisesRegex(exc.DBAPIError, "row-level security policy"),
            ):
                self._link(1, project_id=project_id, tag_id=tag_id)

    def test_link_policies_allow_bypass(self) -> None:
        self._link(1, project_id=3, tag_id=3, bypass=True)

    def test_link_policies_read_update_and_delete(self) -> None:
        with self._session(1) as sess:
            links = sess.execute(sqlalchemy.select(project_tags)).all()
            self.assertEqual([tuple(link) for link in links], [(1, 1)])
            # Another account's link is not deleted.
            deleted = sess.execute(
                sqlalchemy.delete(project_tags).where(project_tags.c.project_id == 2)
            )
            self.assertEqual(deleted.rowcount, 0)  # type: ignore[attr-defined]
            updated = sess.execute(sqlalchemy.update(project_tags).values(tag_id=3))
            self.assertEqual(updated.rowcount, 1)  # type: ignore[attr-defined]
            sess.rollback()
        with self._session(1) as sess:
            with self.assertRaisesRegex(exc.DBAPIError, "row-level security policy"):
                sess.execute(sqlalchemy.update(project_tags).values(tag_id=2))
            sess.rollback()
        with self._session(1) as sess:
            deleted = sess.execute(sqlalchemy.delete(project_tags))
            self.assertEqual(deleted.rowcount, 1)  # type: ignore[attr-defined]
            sess.rollback()

    def test_autogenerate_has_no_diff_once_policies_exist(self) -> None:
        self.assertEqual(self.ops_after, {})


class AutogenerateFromEmptyDatabaseTests(unittest.TestCase):
    """Policies read other tables, so they must only be created once every
    table of the migration exists."""

    def setUp(self) -> None:
        self.postgresql = testing.postgresql.Postgresql(
            postgres_args="-h 127.0.0.1 -F -c logging_collector=off"
        )
        self.addCleanup(self.postgresql.stop)
        url = sqlalchemy.engine.make_url(self.postgresql.url()).set(
            drivername="postgresql+psycopg"
        )
        self.engine = sqlalchemy.create_engine(url)
        self.addCleanup(self.engine.dispose)

    def _upgrade_ops(
        self,
        connection: sqlalchemy.Connection,
        metadata: sqlalchemy.MetaData = Base.metadata,
    ) -> list:
        context = migration.MigrationContext.configure(
            connection, opts={"target_metadata": metadata}
        )
        script = autogenerate.produce_migrations(context, metadata)
        assert script.upgrade_ops is not None
        return list(script.upgrade_ops.ops)

    def _upgrade(self, metadata: sqlalchemy.MetaData) -> None:
        with self.engine.begin() as connection:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(connection)
            )

            def invoke(ops: list) -> None:
                for op in ops:
                    if isinstance(op, alembic_ops_module.ModifyTableOps):
                        invoke(op.ops)
                    else:
                        operations.invoke(op)

            invoke(self._upgrade_ops(connection, metadata))
        with self.engine.connect() as connection:
            self.assertEqual(self._upgrade_ops(connection, metadata), [])

    def test_policies_are_created_after_all_other_changes(self) -> None:
        with self.engine.connect() as connection:
            ops = self._upgrade_ops(connection)

        def creates_policies(op: typing.Any) -> bool:
            return isinstance(op, alembic_ops_module.ModifyTableOps) and any(
                isinstance(sub_op, alembic_ops.CreatePolicyOp) for sub_op in op.ops
            )

        first = next(i for i, op in enumerate(ops) if creates_policies(op))
        self.assertGreater(first, 0)
        for op in ops[first:]:
            self.assertTrue(creates_policies(op))
            self.assertTrue(
                all(isinstance(sub_op, alembic_ops.CreatePolicyOp) for sub_op in op.ops)
            )
        self.assertFalse(any(creates_policies(op) for op in ops[:first]))

    def test_upgrade_from_empty_database(self) -> None:
        self._upgrade(Base.metadata)

    def test_indexes_of_new_tables_are_not_deferred(self) -> None:
        """A foreign key to a uniquely indexed column needs the index, which
        Alembic creates right after its table."""
        IndexBase: typing.Any = _new_base()

        class Author(IndexBase):
            __tablename__ = "authors"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            code = sqlalchemy.Column(sqlalchemy.String, unique=True, index=True)
            __rls_policies__ = _owner_policies()

        class Book(IndexBase):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            author_code = sqlalchemy.Column(
                sqlalchemy.String, sqlalchemy.ForeignKey("authors.code")
            )
            author = orm.relationship(Author)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("author")
            ]

        self.assertIn(Book.__tablename__, IndexBase.metadata.tables)
        self._upgrade(IndexBase.metadata)

    def test_policies_are_created_after_existing_tables_are_altered(self) -> None:
        """Alembic alters existing tables after creating new ones, so a new
        table's policy reading a new column of an existing table must wait."""
        with self.engine.begin() as connection:
            connection.execute(
                sqlalchemy.text("CREATE TABLE authors (id INTEGER PRIMARY KEY)")
            )
        AlterBase: typing.Any = _new_base()

        class Author(AlterBase):
            __tablename__ = "authors"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            enabled = sqlalchemy.Column(sqlalchemy.Boolean)
            __rls_policies__ = _owner_policies()

        class Book(AlterBase):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            author_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("authors.id")
            )
            author = orm.relationship(
                Author,
                primaryjoin=lambda: sqlalchemy.and_(
                    Book.author_id == Author.id, Author.enabled == sql.true()
                ),
            )
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("author")
            ]

        self.assertIn(Book.__tablename__, AlterBase.metadata.tables)
        self._upgrade(AlterBase.metadata)

    def test_outdated_helper_function_is_replaced(self) -> None:
        self._upgrade(Base.metadata)
        with self.engine.begin() as connection:
            connection.execute(
                sqlalchemy.text(
                    f"CREATE OR REPLACE FUNCTION {_PROJECTS_VISIBLE}(integer) "
                    "RETURNS boolean LANGUAGE plpgsql STABLE AS "
                    "$$ BEGIN RETURN true; END $$"
                )
            )
        with self.engine.connect() as connection:
            (op,) = self._upgrade_ops(connection)
        self.assertIsInstance(op, alembic_ops.CreateRowVisibleFunctionOp)
        self.assertTrue(op.replaces)
        # The previous version is not known, so a downgrade leaves the
        # function in place.
        self.assertIsInstance(op.reverse(), alembic_ops.CreateRowVisibleFunctionOp)
        self._upgrade(Base.metadata)

    def test_unused_helper_function_is_dropped_last(self) -> None:
        self._upgrade(Base.metadata)
        stale = policy.RowVisibleFunction("authors", "id", "INTEGER")
        with self.engine.begin() as connection:
            connection.execute(sqlalchemy.text(stale.create_sql))
            connection.execute(sqlalchemy.text("ALTER TABLE tags ADD COLUMN x int"))
        with self.engine.connect() as connection:
            ops = self._upgrade_ops(connection)
        self.assertIsInstance(ops[-1], alembic_ops.DropRowVisibleFunctionOp)
        self.assertEqual(ops[-1].to_function(), stale)
        reverse = ops[-1].reverse()
        self.assertIsInstance(reverse, alembic_ops.CreateRowVisibleFunctionOp)
        self.assertEqual(reverse.to_function(), stale)
        self._upgrade(Base.metadata)
        with self.engine.connect() as connection:
            self.assertIsNone(
                connection.execute(
                    sqlalchemy.text("SELECT to_regprocedure(:signature)"),
                    {"signature": stale.signature},
                ).scalar_one()
            )

    def _authors_and_books(self, with_enabled: bool) -> typing.Any:
        """Books follow their author; with ``with_enabled``, only enabled
        authors, so the books' policy reads ``authors.enabled``."""
        VersionBase: typing.Any = _new_base()

        class Author(VersionBase):
            __tablename__ = "authors"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            if with_enabled:
                enabled = sqlalchemy.Column(sqlalchemy.Boolean)
            __rls_policies__ = _owner_policies()

        class Book(VersionBase):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            author_id = sqlalchemy.Column(
                sqlalchemy.Integer, sqlalchemy.ForeignKey("authors.id")
            )
            if with_enabled:
                author = orm.relationship(
                    Author,
                    primaryjoin=lambda: sqlalchemy.and_(
                        Book.author_id == Author.id,
                        Author.enabled == sql.true(),
                    ),
                )
            else:
                author = orm.relationship(Author)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("author")
            ]

        VersionBase.models = (Author, Book)
        return VersionBase

    def test_policies_are_dropped_before_columns_they_read(self) -> None:
        self._upgrade(self._authors_and_books(with_enabled=True).metadata)
        self._upgrade(self._authors_and_books(with_enabled=False).metadata)

    def _books_with_tags(self, with_tags: bool) -> typing.Any:
        """With ``with_tags``, books follow their tags (so the books' policy
        reads ``book_tags`` and ``tags``); otherwise books have an owner and
        the ``book_tags`` association table is dropped."""
        VersionBase: typing.Any = _new_base()
        models: list[typing.Any] = []
        if with_tags:
            book_tags = sqlalchemy.Table(
                "book_tags",
                VersionBase.metadata,
                sqlalchemy.Column(
                    "book_id", sqlalchemy.ForeignKey("books.id"), primary_key=True
                ),
                sqlalchemy.Column(
                    "tag_id", sqlalchemy.ForeignKey("tags.id"), primary_key=True
                ),
            )
            register.table_policies(book_tags, [_owner_policy("tag_id")])

        class Tag(VersionBase):
            __tablename__ = "tags"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        models.append(Tag)

        class Book(VersionBase):
            __tablename__ = "books"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            owner_id = sqlalchemy.Column(sqlalchemy.Integer)
            if with_tags:
                tags = orm.relationship("Tag", secondary=book_tags)
                __rls_policies__: typing.ClassVar[_Policies] = [
                    policy.Policy.from_relationship("tags")
                ]
            else:
                __rls_policies__ = _owner_policies("owner_id")

        models.append(Book)
        VersionBase.models = models
        return VersionBase

    def test_policies_are_dropped_before_tables_they_read(self) -> None:
        self._upgrade(self._books_with_tags(with_tags=True).metadata)
        self._upgrade(self._books_with_tags(with_tags=False).metadata)

    def test_whole_relationship_graph_is_removed(self) -> None:
        self._upgrade(self._books_with_tags(with_tags=True).metadata)
        empty = _new_base().metadata
        with self.engine.connect() as connection:
            ops = self._upgrade_ops(connection, empty)
        # The books' policy reads book_tags, so it is dropped explicitly
        # before any table.
        first_table_drop = next(
            i
            for i, op in enumerate(ops)
            if isinstance(op, alembic_ops_module.DropTableOp)
        )
        policy_drops = [
            (i, op.table_name)
            for i, op in enumerate(ops)
            if isinstance(op, alembic_ops_module.ModifyTableOps)
            and any(isinstance(sub, alembic_ops.DropPolicyOp) for sub in op.ops)
        ]
        self.assertIn("books", [table for _, table in policy_drops])
        self.assertTrue(all(i < first_table_drop for i, _ in policy_drops))
        # Alembic drops removed tables in no particular order, ignoring their
        # foreign keys, so drop the association table first.
        ops.sort(
            key=lambda op: (
                isinstance(op, alembic_ops_module.DropTableOp)
                and op.table_name != "book_tags"
            )
        )
        with self.engine.begin() as connection:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(connection)
            )
            for op in ops:
                for sub in (
                    op.ops
                    if isinstance(op, alembic_ops_module.ModifyTableOps)
                    else [op]
                ):
                    operations.invoke(sub)
        with self.engine.connect() as connection:
            self.assertEqual(self._upgrade_ops(connection, empty), [])

    def test_helper_function_with_enum_key(self) -> None:
        EnumBase: typing.Any = _new_base()
        kind = sqlalchemy.Enum("novel", "poem", name="book_kind")
        book_tags = sqlalchemy.Table(
            "book_tags",
            EnumBase.metadata,
            sqlalchemy.Column("book_id", kind, sqlalchemy.ForeignKey("books.id")),
            sqlalchemy.Column("tag_id", sqlalchemy.ForeignKey("tags.id")),
        )

        class Tag(EnumBase):
            __tablename__ = "tags"
            id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
            __rls_policies__ = _owner_policies()

        class Book(EnumBase):
            __tablename__ = "books"
            id: sqlalchemy.Column[str] = sqlalchemy.Column(kind, primary_key=True)
            tags = orm.relationship(Tag, secondary=book_tags)
            __rls_policies__: typing.ClassVar[_Policies] = [
                policy.Policy.from_relationship("tags", link_policies=True)
            ]

        EnumBase.models = [Tag, Book]
        self._upgrade(EnumBase.metadata)

    def test_helper_function_ignores_temporary_tables(self) -> None:
        self._upgrade(Base.metadata)
        with self.engine.begin() as connection:
            connection.execute(
                sqlalchemy.text(
                    "CREATE TEMPORARY TABLE projects (id integer); "
                    "INSERT INTO projects VALUES (999)"
                )
            )
            self.assertFalse(
                connection.execute(
                    sqlalchemy.text(f"SELECT {_PROJECTS_VISIBLE}(999)")
                ).scalar_one()
            )

    def test_helper_function_ops_escape_colons(self) -> None:
        with self.engine.begin() as connection:
            operations = alembic_operations.Operations(
                migration.MigrationContext.configure(connection)
            )
            op = alembic_ops.CreateRowVisibleFunctionOp("b :c", "id", "INTEGER")
            operations.invoke(op)
            operations.invoke(op.reverse())

    def _stale_function_ops(self, include_name: typing.Any) -> list:
        with self.engine.connect() as connection:
            context = migration.MigrationContext.configure(
                connection,
                opts={"target_metadata": Base.metadata, "include_name": include_name},
            )
            script = autogenerate.produce_migrations(context, Base.metadata)
        assert script.upgrade_ops is not None
        return [
            op
            for op in script.upgrade_ops.ops
            if isinstance(op, alembic_ops.DropRowVisibleFunctionOp)
        ]

    def test_stale_function_respects_name_filters(self) -> None:
        self._upgrade(Base.metadata)
        stale = policy.RowVisibleFunction("authors", "id", "INTEGER")
        with self.engine.begin() as connection:
            connection.execute(sqlalchemy.text(stale.create_sql))

        def exclude_authors(name: str, type_: str, parent_names: typing.Any) -> bool:
            return not (type_ == "table" and name == "authors")

        self.assertEqual(self._stale_function_ops(exclude_authors), [])
        (drop,) = self._stale_function_ops(lambda *_: True)
        self.assertEqual(drop.to_function(), stale)

    def test_function_used_by_another_base_is_kept(self) -> None:
        self._upgrade(Base.metadata)
        stale = policy.RowVisibleFunction("authors", "id", "INTEGER")
        with self.engine.begin() as connection:
            connection.execute(sqlalchemy.text(stale.create_sql))
            connection.execute(
                sqlalchemy.text(
                    "CREATE TABLE other (author_id integer); "
                    "ALTER TABLE other ENABLE ROW LEVEL SECURITY; "
                    f"CREATE POLICY p ON other USING ({stale.name}(author_id))"
                )
            )

        def exclude_other(name: str, type_: str, parent_names: typing.Any) -> bool:
            return not (type_ == "table" and name == "other")

        self.assertEqual(self._stale_function_ops(exclude_other), [])


if __name__ == "__main__":
    unittest.main()
