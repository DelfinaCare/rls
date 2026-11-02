# rls

Adds PostgreSQL row-level security (RLS) support to your Python application by extending `sqlalchemy` and `alembic`.

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

#### Policy.from_sqla

`Policy.from_sqla` compiles a SQLAlchemy expression into a single policy:

- `expr`: a lambda returning a SQLAlchemy boolean expression (see [Expressions](#expressions))
- `condition_args`: the `ConditionArg`s passed to `expr`
- `cmd`: the `Command` the policy applies to (one policy per command)
- `name`: optional name prefix; defaults to `<policy_type>_<comparator names>_<cmd>`
- `policy_type`: `PolicyType.permissive` (default) or `PolicyType.restrictive`
- `allow_bypass_rls`: whether the policy can be bypassed with `bypass_rls()` (default `True`)

The final policy name always ends with a short hash of the policy definition, so changing a policy changes its name (see the [alembic docs](./alembic.md)).

#### ConditionArg

`ConditionArg` describes a variable that will be set on the PostgreSQL session before a query runs, allowing the policy expression to reference it.

- `comparator_name`: the PostgreSQL session variable name
- `type`: the SQLAlchemy type of the variable

```python
from sqlalchemy import Integer

ConditionArg(comparator_name="account_id", type=Integer)
```

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

You can then generate a revision and run `alembic upgrade head` as normal — the policies will be created or dropped automatically.
For details on the custom Alembic operations used internally, see the [alembic docs](./alembic.md).
If you are not using alembic, you can call `rls.create_policies` directly.

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
