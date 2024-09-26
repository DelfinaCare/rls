### Custom expression

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
