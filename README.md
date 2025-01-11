# rls

a package to provide row level security seamlessly to your python app by extending `sqlalchemy` and `alembic`.

---

## Installation

### Package

```bash
pip install rls
```

or if you are using poetry

```bash
poetry add rls
```

### Source Code

After cloning the repo use it as you would use the package but import from your local cloned files


---

## Usage Example

### Creating Policies

```python
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import column
from rls.schemas import Permissive, Command, ConditionArg
import Typing

# To avoid deletion by pre-commit hooks
_Any = typing.Any

Base = declarative_base()  # type: Any


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)

    __rls_policies__ = [
        Permissive(
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=[Command.select, Command.update],
            custom_expr=lambda x: column("id") == x,
            custom_policy_name="equal_to_accountId_policy",
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
        Permissive(
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=[Command.select, Command.update],
            custom_expr=lambda x: column("owner_id") == x,
            custom_policy_name="equal_to_accountId_policy",
        ),
        Permissive(
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=[Command.select],
            custom_expr=lambda x: column("owner_id") > x,
            custom_policy_name="greater_than_accountId_policy",
        ),
        Permissive(
            condition_args=[
                ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=[Command.all],
            custom_expr=lambda x: column("owner_id") <= x,
            custom_policy_name="smaller_than_or_equal_accountId_policy",
        ),
    ]
```

#### Condition Args

`ConditionArg` is a class that takes two arguments:
- `comparator_name`: the name of the variable that will be passed in the context
- `type`: the sqlalchemy `sqltype` of the variable that will be passed in the context

```python
from sqlalchemy import Integer

ConditionArg(comparator_name="account_id", type=Integer)
```

#### Commands

`Command` is an enum for possible sql commands, it has the following values:
- `select` : for select queries
- `insert` : for insert queries
- `update` : for update queries
- `delete` : for delete queries
- `all` : for all queries



#### Expressions
You can utilize lambda functions to create policies dynamically

```python
from sqlalchemy import column

# ConditionArg(comparator_name="account_id", type=Integer),

lambda x: x > column("owner_id")
```
this would take the column owner_id from the table and compare it with the first value passed in the context
in this case would be the `account_id`

#### Alembic
`alembic` must be initialized  to be used when creating policies


the rls policies are registered as metadata info and can be used with alembic
but first in alembic `env.py` before setting

```python
target_metadata = Base.metadata
```

call our rls base wrapper instead

```python
from rls.alembic_rls import rls_base_wrapper

target_metadata = rls_base_wrapper(Base).metadata
```

which returns a base that its rls policies metadata set.

Now all you have to do is create a revision and run upgrade head with `alembic` for the policies to be created or dropped.

for more info on handling alembic and it's custom operations check our [alembic docs](./alembic.md)

---

### Using the policies

now that we have created the policies how are we going to use it?

we have a custom sqlalchemy session class called `RlsSession` that extends sqlaclhemy's `Session` which must be used or extended.

and you have to pass the context which the session variables values will be taken from which should extend a `pydantic Base Model` and bind an `engine` to it.

```python
class MyContext(BaseModel):
    account_id: int
    provider_id: int


context = MyContext(account_id=1, provider_id=2)
session = RlsSession(context=context, bind=engine)

res = session.execute(text("SELECT * FROM users")).fetchall()

# Bypassing the rls policies with a context manager

with session.bypass_rls() as session:
    res2 = session.execute(text("SELECT * FROM items")).fetchall()
```



you can use this session to talk to your db directly or you can create a session factory
for which we provide our `RlsSessioner`.

which takes two arguments:

- `sessionmaker`: your own created session maker from our `RlsSession` or its subclass
- `context_getter`: an instance of a class that extends `ContextGetter` that has the get context function implemented from which you can extract values from `args` or `kwargs` and assign it to your context variables.

for which you have

```python
from sqlalchemy.orm import sessionmaker
from rls.rls_session import RlsSession
from rls.rls_sessioner import RlsSessioner, ContextGetter
from pydantic import BaseModel
from test.engines import sync_engine as engine
from sqlalchemy import text


class ExampleContext(BaseModel):
    account_id: int
    provider_id: int


# Concrete implementation of ContextGetter
class ExampleContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> ExampleContext:
        account_id = kwargs.get("account_id", 1)
        provider_id = kwargs.get("provider_id", 2)
        return ExampleContext(account_id=account_id, provider_id=provider_id)


my_context = ExampleContextGetter()

session_maker = sessionmaker(
    class_=RlsSession, autoflush=False, autocommit=False, bind=engine
)

my_sessioner = RlsSessioner(sessionmaker=session_maker, context_getter=my_context)



with  my_sessioner(account_id=22, provider_id=99) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res) # output: List of users with account_id = 22 and provider_id = 99


with  my_sessioner(account_id=11, provider_id=44) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res) # output: List of users with account_id = 11 and provider_id = 44
```

---

### Frameworks

#### Fastapi

if you are trying to use the `RlsSessioner` with fastapi you may face some difficulties so that's why there is a ready made function for this integration to be injected in your request handler. For a complete runnable example, please see [`test/fastapi_app.py`](test/fastapi_app.py).


---
## LiCENSE
[MIT](./LICENSE)
