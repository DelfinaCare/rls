# rls

Adds PostgreSQL row-level security (RLS) support to your Python application by extending `sqlalchemy` and `alembic`.

### Goals and threat model

The goal of this package is to protect against **application logic mistakes**, such as a query that forgets to filter by the current account, by making data access rules declarative, easy to understand and easy to audit. Policies live next to the models they protect, and every query run through an `RlsSession` is filtered by them.

It is **not** a defense against hostile SQL (for example SQL injection or untrusted users with direct database access). RLS context values, including `rls.bypass_rls`, are ordinary PostgreSQL settings that any SQL running on the connection can change, by design.

> **Warning: migrating an existing RLS setup.** Once registered with alembic, this package manages RLS for every table in your metadata: autogenerate **drops existing policies** that are not declared in `__rls_policies__` and **disables RLS** on tables that declare no policies. If your database already has RLS policies, read the [migration guide](./migration.md) before using the alembic integration.

---

## Installation

```bash
pip install rls
```

## Usage

### Defining Policies

Attach `__rls_policies__` to any SQLAlchemy model to declare which RLS policies should apply to it. For a full working example see [`test/models.py`](test/models.py).

```python
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)

    __rls_policies__ = [
        Policy.from_sqla(
            expr=lambda x: column("id") == x,
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=Command.all,
        ),
    ]


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    owner = relationship("User")

    __rls_policies__ = [
        Policy.from_sqla(
            expr=lambda x: column("owner_id") == x,
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=Command.all,
        ),
        Policy.from_sqla(
            expr=lambda x: column("owner_id") > x,
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=Command.select,
            name="greater_than_account_id",
        ),
    ]
```

#### RLS mode

By default, row level security is both enabled and forced on every table with policies (`ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`), so the table owner is also subject to the policies. Set `__rls_mode__` on a model to choose the mode per table:

```python
from rls import policy


class AuditLog(Base):
    __tablename__ = "audit_log"

    __rls_policies__ = [...]
    __rls_mode__ = policy.RlsMode.enable  # or "ENABLE"
```

| Value | Effect |
|---|---|
| `RlsMode.enable_and_force` (`"ENABLE_AND_FORCE"`, default) | RLS is enabled and forced; the table owner is subject to the policies |
| `RlsMode.enable` (`"ENABLE"`) | RLS is enabled but not forced; the table owner bypasses the policies |

Changing the mode of an existing table is picked up by alembic autogenerate.

#### Inheritance

Policies are registered against the table that the declaring model maps to:

- **Joined-table inheritance**: a subclass with its own table may declare its own `__rls_policies__` (and `__rls_mode__`), which apply to the subclass's table. The parent's policies stay on the parent's table. A subclass that does not declare `__rls_policies__` adds no policies to its table.
- **Single-table inheritance**: subclasses share the parent's table, so declaring `__rls_policies__` on them raises a `TypeError`. Declare the policies on the class that defines the table.

Policies declared on an unmapped mixin apply to every model using the mixin.

#### Policy.from_sqla

`Policy.from_sqla` compiles a SQLAlchemy expression into a single policy:

- `expr`: a lambda returning a SQLAlchemy boolean expression (see [Expressions](#expressions))
- `condition_args`: the `ConditionArg`s passed to `expr`
- `cmd`: the `Command` the policy applies to (one policy per command)
- `name`: optional name prefix; defaults to `<policy_type>_<comparator names>_<cmd>`
- `policy_type`: `PolicyType.permissive` (default) or `PolicyType.restrictive`
- `allow_bypass_rls`: whether the policy can be bypassed with `bypass_rls()` (default `True`)
- `check_expr`: optional separate `WITH CHECK` expression for `update` and `all` policies, called with the same `condition_args` as `expr`. `expr` is the `USING` expression, which selects the existing rows the policy applies to, while `check_expr` validates the new rows written. Without it, new rows are checked with `expr`. Passing it for other commands raises `ValueError`.
- `roles`: optional list of roles the policy applies to (`TO ...`); defaults to all roles (`PUBLIC`). `PUBLIC`, `CURRENT_USER`, `CURRENT_ROLE` and `SESSION_USER` are rendered as keywords, other names are quoted as needed.

```python
Policy.from_sqla(
    expr=lambda x: column("owner_id") == x,  # rows that can be updated
    check_expr=lambda x: and_(column("owner_id") == x, column("locked") == false()),
    condition_args=[ConditionArg(comparator_name="account_id", type=Integer)],
    cmd=Command.update,
    roles=["app_user"],
)
```

The final policy name always ends with a short hash of the policy definition (type, command, expressions and roles), so changing a policy changes its name (see the [alembic docs](./alembic.md)). Two identical policies with the same name on one table would get the same name, so registering a table whose policies share a name raises `ValueError`; give one of them a different `name` or remove the duplicate.

#### Policy.from_relationship

Most policies follow a relationship: a book belongs to whoever its author belongs to. `Policy.from_relationship` builds such a policy from a `relationship()` of the model, so the join condition does not have to be repeated in a `Policy.from_sqla` expression.

```python
class Author(Base):
    __tablename__ = "authors"

    id = Column(Integer, primary_key=True)

    __rls_policies__ = [
        Policy.from_sqla(
            expr=lambda x: column("id") == x,
            condition_args=[ConditionArg(comparator_name="account_id", type=Integer)],
            cmd=Command.all,
        ),
    ]


class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("authors.id"))

    author = relationship("Author")
    tags = relationship("Tag", secondary=book_tags)

    __rls_policies__ = [
        # A book is accessible when its author is.
        Policy.from_relationship("author"),
    ]
```

The first argument is the name of the relationship attribute. There are two kinds of relationship policy, depending on whether `condition_arg` is passed:

| | Many-to-one (`Book.author`) | Many-to-many (`Book.tags`) |
|---|---|---|
| `from_relationship("...")` | `EXISTS (SELECT 1 FROM authors WHERE authors.id = books.author_id)` | `EXISTS (SELECT 1 FROM book_tags JOIN tags ON tags.id = book_tags.tag_id WHERE books.id = book_tags.book_id)` |
| `from_relationship("...", condition_arg=...)` | `books.author_id = <context value>` | `EXISTS (SELECT 1 FROM book_tags WHERE books.id = book_tags.book_id AND book_tags.tag_id = <context value>)` |

**Without `condition_arg`**, a row is accessible when it is related to at least one row the session can see. Postgres applies the `SELECT` policies of the related table (and of the association table) inside the `EXISTS`, so the book above is accessible exactly when the session can see its author, and a many-to-many row is accessible when the session can see at least one of the rows it is linked to. Policies chain: a `Chapter` with `Policy.from_relationship("book")` follows the book, which follows the author. This also works for one-to-many relationships.

- The related table must declare `__rls_policies__`. Otherwise every row with a related row would be accessible, so a `ValueError` is raised. (For many-to-many it is the association table that must be protected, see [below](#many-to-many-and-one-to-many-relationships).)
- The related table's policies only apply if the querying role is subject to them: it needs `SELECT` on the related (and association) table and must not bypass their RLS (a table owner does when the table's [RLS mode](#rls-mode) is `enable`).
- A row with no related row (e.g. a `NULL` foreign key) is only accessible with `bypass_rls()`.
- Relationship policies must not read each other's tables in a cycle (e.g. `Book` following `author` while `Author` follows `books`), and a self-referential relationship cannot be followed. Postgres rejects both as infinite recursion, so they raise a `ValueError`. The cycle check does not take `roles` into account.
- A relationship to a single table inheritance subclass raises a `ValueError`: SQLAlchemy limits it to that subclass with a criterion that is not part of the join condition, so the policy would also match rows of the other classes sharing the table.

**With `condition_arg`**, a row is accessible when it is related to the row whose primary key equals that context value, without consulting the related table's policies:

```python
account_id = ConditionArg(comparator_name="account_id", type=Integer)

# Many-to-one: books.author_id = <account_id>
Policy.from_relationship("author", condition_arg=account_id)

# Many-to-many: the association table links the row to <account_id>
Policy.from_relationship("members", condition_arg=account_id)
```

This is supported for many-to-one and many-to-many relationships that join on the related model's single-column primary key, and only when that key equality is the whole join condition (for many-to-many, the whole `secondaryjoin`): extra criteria such as `Book.enabled == true()` would be dropped from the policy. Anything else raises a `ValueError` and needs `Policy.from_sqla`. Without `condition_arg`, the full join condition is kept.

##### Many-to-many and one-to-many relationships

A many-to-one relationship is stored on the row itself (its foreign key), so the policy also checks the rows that are written: a book can only be inserted for, or moved to, an author the session can access. The links of the other relationships are stored elsewhere, which has two consequences.

**The association table must be protected.** Whoever can write to the association table of a many-to-many relationship decides who can access the rows it links: a session that could insert a link from somebody else's row to one of its own tags would gain access to that row. `from_relationship` therefore raises a `ValueError` unless the association table has policies of its own. The simplest way is to generate them with `link_policies=True`:

```python
class Book(Base):
    __tablename__ = "books"
    id = Column(Integer, primary_key=True)
    tags = relationship("Tag", secondary=book_tags)
    __rls_policies__ = [Policy.from_relationship("tags", link_policies=True)]
```

This adds these policies to `book_tags`:

| command | a session may … | expression |
|---|---|---|
| `SELECT` | see a link when it can see the tag | `EXISTS (SELECT 1 FROM tags WHERE tags.id = book_tags.tag_id)` |
| `INSERT`, `UPDATE`, `DELETE` | create, change or delete a link when it can see both the book and the tag | `rls_visible_books_id_<hash>(book_tags.book_id) AND EXISTS (…tags…)` |

They take the relationship's `allow_bypass_rls` and `roles`, and they are added to any policies declared with `register.table_policies`.

Checking that the session can see the book needs a helper function. An association-table policy that reads `books` directly is rejected by Postgres with `infinite recursion detected in policy`: the books' policy reads `book_tags`, and Postgres refuses such cycles when it rewrites the query, even though nothing would recurse when it runs. `rls_visible_books_id_<hash>(key)` is a plain `SECURITY INVOKER` PL/pgSQL function, generated for the books table in its schema, that runs `SELECT EXISTS (SELECT 1 FROM public.books WHERE public.books.id = key)` as the session, so the books' own policies decide. Its body is planned separately, which avoids the cycle check, and its query is fixed, so Postgres caches its plan (a batch of 500 links costs about 7 ms more than no check in the [load test](loadtest/README.md)). Each table on the near side of such a relationship gets one function, named `rls_visible_<table>_<key column>_<hash>` (lowercase, at most 63 bytes; the hash keeps different table and column pairs apart). The table is always schema-qualified, so a temporary table cannot shadow it: for a table without a schema, the function is created in, and reads the table from, the `current_schema()` of the connection that creates it, just as policies resolve table names when they are created. Alembic autogenerate creates or updates the functions (`create_rls_row_visible_function(...)`) before the policies that use them and drops the ones no longer used, and `create_policies_no_commit` creates them too. The function is only called when links are written, not when rows are read.

Things to keep in mind with generated link policies:

- A new book has no tags yet, so it is not visible and cannot get its first link: create it and its first link with `bypass_rls()`, or give books another way to be visible (e.g. an owner column).
- Linking a book to a tag makes it visible to everyone who can see that tag. If tags are shared more widely than books, a session can share a book it can see with that wider audience.
- They are only generated for a relationship without `condition_arg` that joins each side to the association table on a single column.

To write the association table's policies yourself, declare them with `register.table_policies`, the equivalent of `__rls_policies__` for a table without a mapped class:

```python
book_tags = Table(
    "book_tags",
    Base.metadata,
    Column("book_id", ForeignKey("books.id"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id"), primary_key=True),
)


def bypass_only(cmd):
    # Nobody passes the expression, so only bypass_rls() sessions do.
    return Policy.from_sqla(
        expr=lambda: false(), condition_args=[], cmd=cmd, name="bypass_only"
    )


register.table_policies(
    book_tags,
    [
        # Sessions can read the links to the tags they can see ...
        Policy.from_sqla(
            expr=lambda: exists().where(Tag.id == column("tag_id")),
            condition_args=[],
            cmd=Command.select,
        ),
        # ... but only change links with bypass_rls().
        bypass_only(Command.insert),
        bypass_only(Command.delete),
    ],
)
```

`table_policies(table, policies, rls_mode=...)` must be called after `register.base_wrapper(Base)` and accepts `Policy` and `ExternalPolicy` objects. `Policy.from_sqla` compiles its expression right away, so a policy that refers to a model (like `Tag` above) has to be declared after it. An association table that is mapped to a class is protected by that class's `__rls_policies__` instead.

Having policies on the association table is necessary, not sufficient: what they allow is up to you. Be careful with write policies that only look at one side of the link, such as "a session may insert links to tags it can see" or "a session may add itself as a member", since they let a session link itself to any row whose id it knows. Because RLS is forced by default and `bypass_rls()` works by being part of each policy's expression, a command with no policy at all is denied even with `bypass_rls()`, which is why the example declares bypass-only write policies rather than none.

**A new row has no links yet.** With a many-to-many or one-to-many relationship policy, a newly inserted row cannot pass the policy's `INSERT` check, so it can only be inserted with `bypass_rls()`. To let ordinary sessions create rows, add an `INSERT` policy saying who may (permissive policies are combined with `OR`):

```python
__rls_policies__ = [
    Policy.from_relationship("tags"),
    Policy.from_sqla(expr=lambda: true(), condition_args=[], cmd=Command.insert),
]
```

This only works when the relationship policy is permissive (the default). Restrictive policies are combined with `AND`, so a restrictive relationship policy that applies to `INSERT` (e.g. with the default `Command.all`) still rejects every unlinked row, whatever other `INSERT` policies allow; limit it to the other commands with `cmd` if new rows should be allowed.

The new row stays inaccessible to its creator until it is linked, and Postgres applies the `SELECT` policies to `INSERT ... RETURNING`, so such inserts cannot return the row (e.g. a server-generated primary key). Creating the row and its first links inside `bypass_rls()`, or adding a policy on a column of the row itself (such as a `created_by` column), avoids both.

`from_relationship` also accepts `link_policies` (see [above](#many-to-many-and-one-to-many-relationships)), `cmd` (default `Command.all`), `name` (default `<policy_type>_<relationship>_<comparator name>_<cmd>`), `policy_type`, `allow_bypass_rls` and `roles`, which behave as in [`Policy.from_sqla`](#policyfrom_sqla). It can be mixed with other policies in `__rls_policies__`.

The join condition is only known once SQLAlchemy has configured the mappers, so `from_relationship` returns a `RelationshipPolicy` declaration rather than a `Policy`. Alembic autogenerate and `create_policies_no_commit` resolve it for you (which configures the mappers, so the related model can be defined later in the file or in another module), and that is when the errors above are raised. Call `rls.policy.resolved_policies(Base.metadata)` to resolve and inspect the policies yourself, for example in a test. The policy has to be declared on the model whose table holds the relationship's columns, which matters for joined-table inheritance.

#### ExternalPolicy

`ExternalPolicy` declares a policy that already exists on the table and is managed outside of this package (e.g. by hand-written migrations). Alembic autogenerate never creates or drops it, and `rls.create_policies.create_policies_no_commit` skips it. It can be mixed with native policies in `__rls_policies__`:

```python
__rls_policies__ = [
    policy.ExternalPolicy(name="legacy_owner_policy"),
    Policy.from_sqla(...),
]
```

`name` must match the policy's name in Postgres exactly. See the [migration guide](./migration.md) for how to use it to adopt existing policies.

#### ConditionArg

`ConditionArg` describes a variable that will be set on the PostgreSQL session before a query runs, allowing the policy expression to reference it.

- `comparator_name`: the name of the context field the value is read from (sent as the `rls.<comparator_name>` setting). It must be a valid Python identifier other than `bypass_rls`.
- `type`: the SQLAlchemy type the variable is cast to, as a class or, for types that take arguments, an instance

```python
from sqlalchemy import DateTime, Enum, Integer

ConditionArg(comparator_name="account_id", type=Integer)
ConditionArg(comparator_name="now", type=DateTime(timezone=True))  # timestamptz
ConditionArg(
    comparator_name="role",
    type=Enum(Role, name="role", values_callable=lambda e: [m.value for m in e]),
)
```

The cast type should match the column the variable is compared with:

| Context field type | `ConditionArg` type |
|---|---|
| `int` | `Integer` (or `BigInteger`, ...) |
| `float` | `Float` |
| `Decimal` | `Numeric` |
| `str` | `String` / `Text` |
| `bool` | `Boolean` |
| `UUID` | `Uuid` |
| `date` | `Date` |
| `time` | `Time`, or `Time(timezone=True)` for `timetz` |
| `datetime` | `DateTime`, or `DateTime(timezone=True)` for `timestamptz` |
| enum | the column's type, e.g. `Integer`, `String` or a native `Enum(..., name=...)` |

Casting an aware `datetime`/`time` to a type without time zone (`DateTime`, `Time`) discards its UTC offset, so use the `timezone=True` variants for aware values. Context enums are sent by `.value`, while SQLAlchemy's `Enum` stores member names by default, so pass `values_callable` (as above) when names and values differ.

#### Commands

`Command` is an enum of SQL operations a policy can target:

| Value | Applies to |
|---|---|
| `select` | SELECT |
| `insert` | INSERT |
| `update` | UPDATE |
| `delete` | DELETE |
| `all` | all of the above |

#### Expressions

Policy expressions are lambdas that receive the `ConditionArg` value(s) and return a SQLAlchemy boolean expression. For example:

```python
from sqlalchemy import column

lambda x: column("owner_id") == x
```

This restricts rows to those whose `owner_id` matches the value of `account_id` supplied in the session context.

#### Alembic

RLS policies are stored as SQLAlchemy metadata and managed through Alembic migrations. In your `env.py`, call `register` to wire up your base:

```python
from rls import register

register.base_wrapper(Base)
target_metadata = Base.metadata
```

To catch a `comparator_name` that does not match a context field (which would otherwise silently hide every row, since unset settings read as `NULL`), pass your context model: `register.base_wrapper(Base, context_model=MyContext)` checks every model's policies, including models mapped later, and raises `ValueError` on a mismatch. `register.validate_context(Base, MyContext)` runs the same check on demand.

You can then generate a revision and run `alembic upgrade head` as normal — the policies will be created or dropped automatically.
For details on the custom Alembic operations used internally, see the [alembic docs](./alembic.md).
Set the `RLS_SUPPRESS_ALEMBIC_GENERATION` environment variable to `1` to stop autogenerate from emitting any RLS operations (see the [migration guide](./migration.md)).
If you are not using alembic, you can call `rls.create_policies.create_policies_no_commit` directly.

```python
register.base_wrapper(Base)
Base.metadata.create_all(engine)
with engine.begin() as connection:
    create_policies.create_policies_no_commit(Base, connection)
```

`create_policies_no_commit` raises a `ValueError` if `Base` was not registered with `register.base_wrapper`. It drops and re-creates each declared policy, so it is safe to call again, but it does not drop policies that are no longer declared. It does not commit: transaction control is left to the caller.

---

### Using Policies at Runtime

Policies are enforced through `RlsSession`, a drop-in replacement for SQLAlchemy's `Session`. You supply a Pydantic context object whose fields match the `comparator_name` values in your policies, plus a bound engine:

```python
class MyContext(BaseModel):
    account_id: int
    provider_id: int


context = MyContext(account_id=1, provider_id=2)
session = RlsSession(context=context, bind=engine)

res = session.execute(text("SELECT * FROM users")).fetchall()

# Temporarily bypass RLS with a context manager
with session.bypass_rls() as session:
    res2 = session.execute(text("SELECT * FROM items")).fetchall()
```

The context is applied to everything the session sends to the database: `execute`/`scalar(s)`, `get`, `refresh`, lazy loads, ORM flushes and `session.connection()` (including later changes to the context or `bypass_rls()` state for statements run directly on that connection). `AsyncRlsSession` behaves the same way.

Context field values are sent to PostgreSQL as text and cast by the policy expression. Supported field types are `str`, `int`, `float`, `bool`, `Decimal`, `UUID`, `datetime`, `date`, `time`, and enums whose values are `str` or `int` (sent by their `.value`, e.g. `"admin"` rather than `"Role.admin"`), as well as `Optional`/`Union` combinations of these. Constrained or aliased forms of these types (e.g. `Annotated[int, ...]`, `pydantic.PositiveInt`, `NewType`, `type` aliases) are also supported, including inside `Optional`. A `None` value matches no rows. Other types (e.g. lists, dicts, `Literal`, nested models, or a field that can only be `None`) raise `TypeError` when the session is created.

Settings are applied with `set_config(..., is_local => true)`, so they only last until the end of the current transaction and never leak to the next user of a pooled connection. They are sent once at the start of each transaction, and again only when they change: entering or exiting `bypass_rls()`, changing a mutable context, or rolling back a savepoint.

#### RlsSessioner

For applications that build a session per request or operation, `RlsSessioner` wraps a `sessionmaker` and a `ContextGetter` to produce ready-to-use `RlsSession` instances.

- `sessionmaker`: a SQLAlchemy `sessionmaker` configured with `class_=RlsSession`
- `context_getter`: a subclass of `ContextGetter` that constructs the context object from arbitrary `args`/`kwargs`

```python
from sqlalchemy.orm import sessionmaker
from rls.session import RlsSession
from rls.rls_sessioner import RlsSessioner, ContextGetter
from pydantic import BaseModel
from test.engines import sync_engine as engine
from sqlalchemy import text


class ExampleContext(BaseModel):
    account_id: int
    provider_id: int


class ExampleContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> ExampleContext:
        return ExampleContext(
            account_id=kwargs.get("account_id", 1),
            provider_id=kwargs.get("provider_id", 2),
        )


session_maker = sessionmaker(
    class_=RlsSession, autoflush=False, autocommit=False, bind=engine
)
my_sessioner = RlsSessioner(
    sessionmaker=session_maker, context_getter=ExampleContextGetter()
)

with my_sessioner(account_id=22, provider_id=99) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res)  # users scoped to account_id=22, provider_id=99

with my_sessioner(account_id=11, provider_id=44) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res)  # users scoped to account_id=11, provider_id=44
```

---

### Frameworks

#### FastAPI

In a FastAPI application every endpoint that touches the database needs the correct RLS context derived from the incoming request (e.g. the authenticated user's `account_id`). Without a structured approach it is easy for individual routes to set the context inconsistently, or to forget to set it at all.

`fastapi_dependency_function` wraps an `RlsSessioner` as a FastAPI dependency so that the RLS context is populated from the request automatically and uniformly for every endpoint that declares it. The session injected into the handler already has the correct PostgreSQL session variables set, ensuring all queries are transparently scoped to the caller's data without any per-endpoint boilerplate.

For a complete runnable example see [`test/fastapi_sample.py`](test/fastapi_sample.py).

---

## LICENSE
[MIT](./LICENSE)
