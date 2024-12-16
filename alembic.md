# Alembic Rls Docs
This is a guide on how to setup and use alembic with the rls package.

## Setting up alembic
alembic must be initialized by our extended metadata first to be used when creating policies.

the rls policies are registered as metadata info and can be used with alembic

in the `env.py` file you must import the `set_metadata_info` from the package and pass it to the `target_metadata` variable

```python
from rls.alembic_rls import set_metadata_info

target_metadata = set_metadata_info(Base).metadata
```

which returns a base that its rls policies metadata set.

## Creating Policies in alembic revisions


To create a policy in alembic revision `manually` you have to keep in mind the following custom alembic operations:
- `op.create_policy` : to create a policy for a table
- `op.drop_policy` : to drop a policy for a table
- `op.enable_rls` : to enable row level security on a table
- `op.disable_rls` : to disable row level security on a table

**Note**: `automatically` creating policies in alembic is supported by the package but it is recommended to always check them before running the upgrade head command

### op.create_policy(table_name: str, policy_name: str, cmd: str, expr: str)
Creates a policy for a table with the given name, definition, policy name, command, and expression

```python
from alembic import op
op.create_policy(
    table_name="accounts",
    definition="PERMISSIVE",
    policy_name="accounts_select",
    cmd="select",
    expr="true"
)
```

### op.drop_policy(table_name: str, policy_name: str, cmd: str, expr: str)
Drops a policy for a table with the given name, policy name, command, and expression

```python
from alembic import op

op.drop_policy(
    table_name="accounts",
    definition="PERMISSIVE",
    policy_name="accounts_select",
    cmd="select",
    expr="true"
)
```

**Note**: the `expr`, `cmd`, `definition` are not used in the drop operation but it is required to be passed for reverse compatibility


### op.enable_rls(table_name: str)
Enables row level security on a table with the given name

```python
from alembic import op

op.enable_rls(
    table_name="accounts"
)
```

### op.disable_rls(table_name: str)
Disables row level security on a table with the given name

```python
from alembic import op

op.disable_rls(
    table_name="accounts"
)
```


## Limitations
- All custom operations are not picked up by mypy and will throw an error when type checked.
