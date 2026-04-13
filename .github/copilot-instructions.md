# Copilot Instructions

## Linting

Lint all Python code with [ruff](https://docs.astral.sh/ruff/).

## Import Style

Import modules or submodules, then access objects through them. Do **not** import objects or functions directly from a submodule.

**Do:**

```python
from module import submodule

submodule.Object()
```

**Don't:**

```python
from module.submodule import MyObject

MyObject()
```

Use one import per line. Do **not** import multiple names in a single `from … import` statement.

**Do:**

```python
from module import submodule_a
from module import submodule_b
```

**Don't:**

```python
from module import submodule_a, submodule_b
```
