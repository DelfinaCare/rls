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
from sqlalchemy.orm import relationship, declarative_base
from rls.schemas import (
    Permissive,
    ExpressionTypes,
    Command,
)


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

class Item1():
    __tablename__ = "items1"

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
                    "operation": Operation.equality,
                    "type": ExpressionTypes.integer,
                    "column_name": "owner_id",
                },
                {
                    "comparator_name": "title",
                    "operation": Operation.equality,
                    "type": ExpressionTypes.text,
                    "column_name": "title",
                }
            ],
            cmd=[Command.all],
            joined_expr="{0} OR {1}",
        )
    ]


class Item2():
    __tablename__ = "items2"

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
                    "operation": Operation.equality,
                    "type": ExpressionTypes.integer,
                    "column_name": "owner_id",
                }
            ],
            cmd=[Command.select],
        )
    ]

```


### Note

`alembic` must be initialized  to be used when creating policies

Now then, there are multiple way you can add expressions:

- `plain expressions`: where you just fill the fields in the condition args and don't specify an expr input so it takes the first value in condition args only as `Item2` table policy.
- `joined expressions`: where you specify multiple condition args elements and input a parametrized joined_expr that has 0 indexed expression numbers e.g: {0} and their joining operations as `Item1` table policy.
- `custom expressions`: where you write expression as you wish but supply us through custom_expr with the session variables as 0 indexed parameters e.g: {0} as `Item` table policy.

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

### Using the policies

now that we have created the policies how are we going to use it?

we have a custom sqlalchemy session class called `RlsSession` which must be used
or extended.

and you have to pass the context which the session variables values will be taken from which should extend a `pydantic Base Model` and bind an `engine` to it.

```python
class MyContext(BaseModel):
    account_id: int
    provider_id: int


context = MyContext(account_id=1, provider_id=2)
session = RlsSession(context=context, bind=engine)

res = session.execute(text("SELECT * FROM users")).fetchall()
```

you can use this session to talk to your db directly or you can create a session factory
for which we provide our `RlsSessioner`.

which takes two arguments:

- `sessionmaker`: your own created session maker from our `RlsSession` or its subclass
- `context_getter`: an instance of a class that extends `ContextGetter` that has the get context function implemented from which you can extract values from `args` or `kwargs` and assign it to your context variables.

for which you have

```python
# Mock context model
class ExampleContext(BaseModel):
    account_id: int
    provider_id: int


# Concrete implementation of ContextGetter
class ExampleContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> ExampleContext:
        account_id = kwargs.get('acount_id')
        provider_id = kwargs.get('provider_id')

        return ExampleContext(account_id=account_id, provider_id=provider_id)


my_context = ExampleContextGetter()

session_maker = sessionmaker(
    class_=RlsSession, autoflush=False, autocommit=False, bind=engine
)


with RlsSessioner(sessionmaker=session_maker, context_getter=my_context)() as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()

```

---

### Frameworks

#### Fastapi

if you are trying to use the `RlsSessioner` with fastapi you may face some difficulties so that's why there is a ready made function for this integration to be injected in your request handler

```python

from rls.rls_sessioner import fastapi_dependency_function

app = FastAPI()

rls_sessioner = RlsSessioner(sessionmaker=session_maker, context_getter=my_context)
my_session = Depends(fastapi_dependency_function(rls_sessioner))

@app.get("/users")
async def get_users(db: Session = my_session):
    result = db.execute(text("SELECT * FROM users")).all()
    return dict(result)
```
