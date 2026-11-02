import enum
import inspect
import typing

import pydantic
import sqlalchemy
from sqlalchemy import sql
from sqlalchemy.sql import elements

from . import _sql_gen

_CONDITION_ARGS_PREFIX = "rls"


class Command(str, enum.Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class PolicyType(str, enum.Enum):
    permissive = "PERMISSIVE"
    restrictive = "RESTRICTIVE"


class ConditionArg(pydantic.BaseModel):
    comparator_name: str
    type: type[sql.sqltypes.TypeEngine]


def _wrap_rls_value_setting(
    value_name: str, value_type: type[sql.sqltypes.TypeEngine]
) -> elements.ColumnElement:
    return sql.func.nullif(
        sql.func.current_setting(f"{_CONDITION_ARGS_PREFIX}.{value_name}", True),
        "",
    ).cast(value_type)


def compile_sqla_expr(
    expr: typing.Callable[..., elements.ColumnElement],
    condition_args: list[ConditionArg] | None,
    allow_bypass_rls: bool = True,
) -> str:
    """Validate and compile a custom expression into a SQL string.

    Returns the compiled SQL expression string.
    """

    condition_args_length = len(condition_args) if condition_args is not None else 0
    lambda_args_length = len(inspect.signature(expr).parameters)
    if condition_args_length != lambda_args_length:
        raise ValueError(
            f"Length mismatch for arguments. Expected {condition_args_length}, got {lambda_args_length}"
        )

    args = []
    for arg in condition_args or []:
        args.append(_wrap_rls_value_setting(arg.comparator_name, arg.type))

    clause_element = expr(*args)

    if not isinstance(clause_element.type, sqlalchemy.Boolean):
        raise ValueError(  # noqa: TRY004 - Preserve the public exception type.
            "Expression does not evaluate to a Boolean value"
        )

    if allow_bypass_rls:
        clause_element = sql.or_(
            clause_element,
            _wrap_rls_value_setting("bypass_rls", sqlalchemy.Boolean) == True,
        )

    return str(clause_element.compile(compile_kwargs={"literal_binds": True}))


class Policy(pydantic.BaseModel):
    """A single row-level security policy attached to a database table."""

    cmd: Command = Command.all
    expr: str
    name: str
    policy_type: PolicyType = PolicyType.permissive

    @classmethod
    def from_sqla(
        cls,
        expr: typing.Callable[..., elements.ColumnElement],
        condition_args: list[ConditionArg],
        cmd: Command,
        name: str | None = None,
        allow_bypass_rls: bool = True,
        policy_type: PolicyType = PolicyType.permissive,
    ) -> "Policy":
        """Build a policy from a SQLAlchemy expression.

        The policy name ends with a short hash of the policy definition
        (type, command and compiled expression).  Postgres rewrites policy
        expressions when storing them, so alembic autogenerate detects
        changes by comparing policy names rather than expressions.
        """
        compiled_expr = compile_sqla_expr(expr, condition_args, allow_bypass_rls)
        if name is None:
            name_parts: list[str] = [policy_type.value]
            name_parts.extend(arg.comparator_name for arg in condition_args)
            name_parts.append(cmd.value)
            name = "_".join(name_parts)
        hashed_name = _sql_gen.hashed_policy_name(
            name.lower(), f"{policy_type.value} {cmd.value} {compiled_expr}"
        )
        return cls(
            expr=compiled_expr, cmd=cmd, name=hashed_name, policy_type=policy_type
        )

    def render_policy(self, table_name: str) -> sqlalchemy.TextClause:
        """Generate a SQL CREATE POLICY statement."""

        # See docs here: https://www.postgresql.org/docs/current/sql-createpolicy.html
        if self.cmd in ["ALL", "SELECT", "DELETE"]:
            return sqlalchemy.text(f"""
                    CREATE POLICY {self.name} ON {table_name}
                    AS {self.policy_type.value}
                    FOR {self.cmd.value}
                    USING ({self.expr})
                    """)

        elif self.cmd == "UPDATE":
            # UPDATE requires both USING and WITH CHECK
            return sqlalchemy.text(f"""
                CREATE POLICY {self.name} ON {table_name}
                AS {self.policy_type.value}
                FOR {self.cmd.value}
                USING ({self.expr})
                WITH CHECK ({self.expr});
            """)

        elif self.cmd == "INSERT":
            return sqlalchemy.text(f"""
                    CREATE POLICY {self.name} ON {table_name}
                    AS {self.policy_type.value}
                    FOR {self.cmd.value}
                    WITH CHECK ({self.expr})
                    """)

        else:
            raise ValueError(f'Unknown policy command "{self.cmd}"')
