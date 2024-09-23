# Fastapi RLS

a package to provide row level security seamlessly to you `fastapi` app by extending `sqlalchemy`.

## Installation

#### Package

Not done yet

#### Source Code

After cloning the repo

install dependencies using poetry

```bash
poetry install
```

Look at the a main.py and models.py for a an example how to use it with FastAPI

```python
# models.py

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from rls.schemas import Permissive, Operation, ExpressionTypes, Command
from rls.register_rls import register_rls
from rls.database import Base

# Register RLS policies
register_rls(Base)


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
            condition_args=[{
                "comparator_name": "user_id",
                "comparator_source": ComparatorSource.bearerTokenPayload,
                "operation": Operation.equality,
                "type": ExpressionTypes.integer,
                "column_name": "owner_id",
            }],
            cmd=[Command.all],
        )
    ]

```

```python
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


from rls.database import get_session
from test.models import Item

from .engines import async_engine as db_engine


app = FastAPI()

Session = Depends(get_session(db_engine))


@app.get("/users/items")
async def get_users(db: AsyncSession = Session):
    stmt = select(Item)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return items

```

#### Custom expression

The user gives us a parametrized expression and array of conidition_args

```python
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
            expr= "{0} AND ({1} OR {2})",
        )
    ]
```

you can pass multiple expressions and in the `expr` field specify their joining conditions.
#### `Note`:
- the valid logical joining operators as of now are `AND` and `OR`
- if no `expr` is given only the first policy in the array of `condition_args` is taken

#### Run Tests

No e2e tests done yet

## API

These functions provide a structured way to handle database sessions and enforce row-level security (RLS) in your application. If you're working with SQLAlchemy models and need a secure and efficient way to manage database access, here's how you can use them:

### `register_rls(Base: Type[DeclarativeMeta])`

This function is used to automatically apply Row-Level Security (RLS) policies to your SQLAlchemy models. From the user's perspective:

- **When to Use**: Call this function when setting up your SQLAlchemy models (typically during application initialization).
- **Purpose**: It ensures that RLS policies are applied after creating tables in the database. This helps enforce fine-grained access control, allowing you to control which rows of data users are allowed to access based on the defined policies.
- **How it Works**: It listens for table creation events and applies security policies automatically, so you don't have to manually enforce them for each table.

### `get_session(db_engine: Engine)`

This function returns the appropriate session factory based on the type of database engine passed to it. It supports both synchronous and asynchronous engines.

**Parameters**:
- db_engine:
  -  The database engine (either synchronous Engine or asynchronous AsyncEngine).

**Behavior**:
- Engine Binding:
  - It binds the engine to manage database connections.
- Session Factory:
  - Returns get_async_session if the engine is asynchronous.
  - Returns get_sync_session if the engine is synchronous.
  - Error Handling: Raises a ValueError if an invalid engine type is provided.

## Examples

using the models.py and main.py found in source code installation

you can send a request with curl for example :

```bash
curl -H
"Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6Ik9tYXIgR2hhaXRoIiwiaWF0IjoxNTE2MjM5MDIyfQ.sk8xw3duwaNnLM7BwrqXmI_k2Kov3hkXLs7Mb9S6M38 "
localhost:8000/users/items
```
Note: this token payload is :
```json
{
  "sub": "1",
  "name": "Omar Ghaith",
  "role": "admin",
  "iat": 1516239022
}
```

it will return only the items owned by owner whose id is 2 as specified in the policy

```json
[
    {
        "description": "Description for item3",
        "owner_id": 2,
        "id": 3,
        "title": "item3"
    },
    {
        "description": "Description for item4",
        "owner_id": 2,
        "id": 4,
        "title": "item4"
    }
]
```

noting that the items table contains

```json
[
    {
        "description": "Description for item1",
        "owner_id": 1,
        "id": 1,
        "title": "item1"
    },
    {
        "description": "Description for item2",
        "owner_id": 1,
        "id": 2,
        "title": "item2"
    },
    {
        "description": "Description for item3",
        "owner_id": 2,
        "id": 3,
        "title": "item3"
    },
    {
        "description": "Description for item4",
        "owner_id": 2,
        "id": 4,
        "title": "item4"
    }
]
```

## License

[MIT](LICENSE)
