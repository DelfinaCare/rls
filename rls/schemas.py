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


class ConditionArg(pydantic.BaseModel):
    comparator_name: str
    type: type[sql.sqltypes.TypeEngine]


class Policy(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(arbitrary_types_allowed=True)

    definition: str
    condition_args: list[ConditionArg] | None = None
    cmd: Command | list[Command]
    custom_expr: typing.Callable[..., elements.ClauseElement] | None = None
    custom_policy_name: str | None = None

    _policy_names: list[str] = pydantic.PrivateAttr(default_factory=list)
    _expr: str = pydantic.PrivateAttr(default="")

    @property
    def policy_names(self) -> list[str]:
        """Getter for the private _policy_names field."""
        return self._policy_names

    @property
    def expression(self) -> str:
        """Getter for the private _expr field."""
        return self._expr

    @expression.setter
    def expression(self, expr: str) -> None:
        self._expr = expr

    def _compile_custom_expr(self, table_name: str) -> None:
        """Validate and compile the custom expression into a SQL string."""
        if self.custom_expr is None:
            raise ValueError(
                f"`custom_expr` must be defined for table `{table_name}`. "
                "If you're constructing expressions dynamically, provide a callable."
            )

        condition_args_length = (
            len(self.condition_args) if self.condition_args is not None else 0
        )
        lambda_args_length = len(inspect.signature(self.custom_expr).parameters)
        if condition_args_length != lambda_args_length:
            raise ValueError(
                f"Length mismatch for arguments. Expected {condition_args_length}, got {lambda_args_length}"
            )

        args = []
        for arg in self.condition_args or []:
            wrapped_value = sql.func.nullif(
                sql.func.current_setting(
                    f"{_CONDITION_ARGS_PREFIX}.{arg.comparator_name}", True
                ),
                "",
            ).cast(arg.type)
            args.append(wrapped_value)

        compiled = self.custom_expr(*args)

        if not isinstance(compiled.type, sqlalchemy.Boolean):
            raise ValueError("Expression does not evaluate to a Boolean value")

        self._expr = str(compiled.compile(compile_kwargs={"literal_binds": True}))

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd

        self._compile_custom_expr(table_name=table_name)

        # Reset policy names for this call so re-invocations don't accumulate duplicates.
        self._policy_names = []
        policy_lists = []

        for cmd in commands:
            cmd_value = cmd.value

            if self.custom_policy_name is not None:
                policy_name = (
                    f"{table_name}_{self.custom_policy_name}"
                    f"_{cmd_value}_policy_{name_suffix}".lower()
                )
            else:
                policy_name = (
                    f"{table_name}_{self.definition}"
                    f"_{cmd_value}_policy_{name_suffix}".lower()
                )

            self._policy_names.append(policy_name)

            generated_policy = _sql_gen.generate_rls_policy(
                cmd=cmd_value,
                definition=self.definition,
                policy_name=policy_name,
                table_name=table_name,
                expr=self._expr,
            )
            policy_lists.append(generated_policy)
        return policy_lists

    def __eq__(self, other):
        if not isinstance(other, Policy):
            return NotImplemented

        definition_check = self.definition == other.definition
        cmd_check = self.cmd == other.cmd
        expression_check = _sql_gen.compare_between_policy_sql_expressions(
            self.expression, other.expression
        )

        return definition_check and cmd_check and expression_check

    def __str__(self):
        return f"Policy(definition={self.definition}, cmd={self.cmd}, expression={self.expression})"


class Permissive(Policy):
    definition: typing.Literal["PERMISSIVE"] = "PERMISSIVE"


class Restrictive(Policy):
    definition: typing.Literal["RESTRICTIVE"] = "RESTRICTIVE"
