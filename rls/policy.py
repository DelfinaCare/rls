import hashlib
import inspect
import typing
from enum import Enum

import pydantic
import sqlalchemy
from sqlalchemy import sql
from sqlalchemy.sql import elements

from . import _sql_gen

_CONDITION_ARGS_PREFIX = "rls"


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class PolicyType(str, Enum):
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
        raise ValueError("Expression does not evaluate to a Boolean value")

    if allow_bypass_rls:
        clause_element = sql.or_(
            clause_element,
            _wrap_rls_value_setting("bypass_rls", sqlalchemy.Boolean) == True,
        )

    return str(clause_element.compile(compile_kwargs={"literal_binds": True}))


def policy_changed_checker(db_policy: "Policy", metadata_policy: "Policy") -> bool:
    """Check whether a database policy matches a metadata policy.

    Returns True if the policies are equivalent, False otherwise.
    """
    if db_policy.policy_type != metadata_policy.policy_type:
        return False
    if db_policy.cmd != metadata_policy.cmd:
        return False
    return _sql_gen.compare_between_policy_sql_expressions(
        db_policy.expr, metadata_policy.expr
    )


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
        cmd: list[Command],
        name: str | None = None,
        allow_bypass_rls: bool = True,
        policy_type: PolicyType = PolicyType.permissive,
    ) -> "Policy":
        expr = compile_sqla_expr(expr, condition_args, allow_bypass_rls)
        if name is None:
            name_parts: list[str] = [policy_type.value]
            name_parts.extend(arg.comparator_name for arg in condition_args)
            name_parts.extend(
                [cmd.value for cmd in cmd] if isinstance(cmd, list) else [cmd.value]
            )
            name_parts.append(hashlib.sha256(expr.encode()).hexdigest()[:8])
            name = "_".join(name_parts).lower()
        return cls(expr=expr, cmd=cmd, name=name, policy_type=policy_type)

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
            raise ValueError(f'Unknown policy command "{cmd}"')

    # def __eq__(self, other):
    #     if not isinstance(other, Policy):
    #         return NotImplemented

    #     definition_check = self.definition == other.definition
    #     cmd_check = self.cmd == other.cmd
    #     expression_check = _sql_gen.compare_between_policy_sql_expressions(
    #         self.expression, other.expression
    #     )

    #     return definition_check and cmd_check and expression_check

    # def __str__(self):
    #     return f"Policy(definition={self.definition}, cmd={self.cmd.value}, expression={self.expression})"
