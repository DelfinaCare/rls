# Migrating an existing RLS codebase

This guide describes how to move a codebase that already uses PostgreSQL row-level security (RLS), with policies written by hand in migrations or SQL scripts, to this package.

> **Warning**: once `register.base_wrapper(Base)` is called in your alembic `env.py`, alembic autogenerate manages RLS for **every table in your metadata**. Policies on those tables that are not declared in `__rls_policies__` are **dropped**, and RLS is **disabled** on tables that do not declare any policies. Follow the phases below to avoid clobbering existing policies.

The migration happens in three phases. Each phase can be deployed and verified on its own.

## Phase 1: switch the runtime code

Start using `RlsSession` / `AsyncRlsSession` (or `RlsSessioner`) at runtime, without touching alembic.

`RlsSession` sets each context field with `set_config('rls.<field name>', <value>, true)` at the start of every transaction (see [Using Policies at Runtime](./README.md#using-policies-at-runtime)). Your existing policies must read the same settings, e.g. `current_setting('rls.account_id', true)`. If they use different setting names, either name your context fields to match, or update the policies with a hand-written migration first.

Note that `session.bypass_rls()` only affects policies that check `rls.bypass_rls`. Policies created by this package do this by default (see `allow_bypass_rls`), but your existing policies will not until they are rewritten in [phase 3](#phase-3-rewrite-external-policies-as-native-policies).

Do **not** call `register.base_wrapper` in your alembic `env.py` during this phase. As an extra safeguard against it being added by accident, set the `RLS_SUPPRESS_ALEMBIC_GENERATION` environment variable wherever alembic revisions are generated (developer machines, CI):

```bash
export RLS_SUPPRESS_ALEMBIC_GENERATION=1
```

While it is set to `1`, `true`, `yes` or `on` (case-insensitive), autogenerate emits no RLS operations at all (`enable_rls`, `disable_rls`, `create_policy` or `drop_policy`). Hand-written migrations that call these operations still run as normal.

## Phase 2: declare existing policies as `ExternalPolicy`

Next, let this package manage RLS, but declare every existing policy as an `ExternalPolicy`. An `ExternalPolicy` tells autogenerate that a policy with that name exists on the table and is managed elsewhere: it is never dropped (or created) by autogenerate, and `rls.create_policies` skips it.

List the existing policies and RLS settings of each table with:

```sql
SELECT schemaname, tablename, policyname FROM pg_policies ORDER BY 1, 2, 3;

SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relrowsecurity;
```

and declare them on the corresponding models:

```python
from rls import policy


class Item(Base):
    __tablename__ = "items"

    __rls_policies__ = [
        policy.ExternalPolicy(name="items_owner_policy"),
        policy.ExternalPolicy(name="items_select_policy"),
    ]
    # Only if FORCE ROW LEVEL SECURITY is not set on the table (see below).
    __rls_mode__ = policy.RlsMode.enable
```

Things to check:

- The `name` must match `pg_policies.policyname` exactly, including case.
- **Every table with RLS enabled** must declare `__rls_policies__` with at least one entry, otherwise autogenerate disables RLS on it. Tables with RLS enabled but no policies at all (deny-all tables) cannot be represented yet, so exclude them from autogenerate (e.g. with alembic's `include_object`).
- Set `__rls_mode__` to match the table's current `FORCE` setting (`relforcerowsecurity`). Tables default to `RlsMode.enable_and_force`, so a table with RLS enabled but not forced would otherwise get an `enable_rls` operation that forces RLS. That may be what you want, but it is a behaviour change, since the table owner becomes subject to the policies.

Then add `register.base_wrapper(Base)` to your alembic `env.py` (see the [alembic docs](./alembic.md)), unset `RLS_SUPPRESS_ALEMBIC_GENERATION`, and autogenerate a revision. It should contain **no** RLS operations. If it does, fix your declarations before going further: a `drop_policy` means a policy is missing from `__rls_policies__`, and `enable_rls`/`disable_rls` mean `__rls_policies__` or `__rls_mode__` do not match the database.

## Phase 3: rewrite external policies as native policies

Finally, replace each `ExternalPolicy` with a native `Policy.from_sqla` policy, at your own pace. This does not have to happen all at once: a table may mix external and native policies, and you can convert one policy, one table or everything per revision.

```python
class Item(Base):
    __tablename__ = "items"

    __rls_policies__ = [
        # Replaces policy.ExternalPolicy(name="items_owner_policy")
        policy.Policy.from_sqla(
            expr=lambda x: column("owner_id") == x,
            condition_args=[
                policy.ConditionArg(comparator_name="account_id", type=Integer),
            ],
            cmd=policy.Command.all,
        ),
        policy.ExternalPolicy(name="items_select_policy"),
    ]
```

The next autogenerated revision drops the old policy and creates the new one in the same migration, so the table is never left without a policy.
