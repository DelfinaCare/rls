import inspect
from enum import Enum
from typing import Callable
from typing import List
from typing import Literal
from typing import Optional
from typing import Type
from typing import Union

import pydantic
import sqlalchemy
from sqlalchemy import sql
from sqlalchemy.sql import elements


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class ConditionArg(pydantic.BaseModel):
    comparator_name: str
    type: Type[sql.sqltypes.TypeEngine]


class Policy(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(arbitrary_types_allowed=True)

    definition: str
    condition_args: Optional[List[ConditionArg]] = None
    cmd: Union[Command, List[Command]]
    custom_expr: Optional[Callable[..., elements.ClauseElement]] = None
    custom_policy_name: Optional[str] = None

    _policy_names: List[str] = pydantic.PrivateAttr(default_factory=list)
    _compiled_custom_expr: Optional[elements.ClauseElement] = pydantic.PrivateAttr(
        default=None
    )
    _expr: str = pydantic.PrivateAttr(default="")
    _policy_suffix: str = pydantic.PrivateAttr(default="")
    _condition_args_prefix: str = pydantic.PrivateAttr(default="rls")

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

    def _ensure_boolean(self):
        """
        Ensures that the given expression evaluates to a Boolean value.
        Raises ValueError if the expression is not of Boolean type.
        """
        if isinstance(self._compiled_custom_expr.type, sqlalchemy.Boolean):
            return True

        raise ValueError("Expression does not evaluate to a Boolean value")

    def _validate_arguments_length(self):
        condition_args_length = (
            len(self.condition_args) if self.condition_args is not None else 0
        )
        lambda_args_length = len(inspect.signature(self.custom_expr).parameters)
        if condition_args_length != lambda_args_length:
            raise ValueError(
                f"Length mismatch for arguments. Expected {condition_args_length}, got {lambda_args_length}"
            )
        return True

    def _convert_lambda_to_clause_element(self):
        """Convert the lambda function to a SQLAlchemy expression."""
        args = []
        for arg in self.condition_args:
            wrapped_value = sql.func.nullif(
                sql.func.current_setting(
                    f"{self._condition_args_prefix}.{arg.comparator_name}", True
                ),
                "",
            ).cast(arg.type)
            args.append(wrapped_value)
        self._compiled_custom_expr = self.custom_expr(*args)
        self._expr = str(
            self._compiled_custom_expr.compile(compile_kwargs={"literal_binds": True})
        )

    def _get_expr_from_custom_expr(self, table_name: str):
        """Get the SQL expression from the custom expression with RLS prefixing."""
        if self.custom_expr is not None:
            self._validate_arguments_length()

            self._convert_lambda_to_clause_element()

            self._ensure_boolean()
        else:
            raise ValueError(
                f"`custom_expr` must be defined for table `{table_name}`. If you're constructing expressions dynamically, "
            )

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        from . import utils

        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd
        self._policy_suffix = name_suffix

        self._get_expr_from_custom_expr(table_name=table_name)

        # Reset policy names for this call so re-invocations don't accumulate duplicates.
        self._policy_names = []
        policy_lists = []

        for cmd in commands:
            cmd_value = cmd.value if isinstance(cmd, Command) else cmd

            policy_name = ""
            if self.custom_policy_name is not None:
                policy_name = (
                    f"{table_name}_{self.custom_policy_name}"
                    f"_{cmd_value}_policy_{self._policy_suffix}".lower()
                )
            else:
                policy_name = (
                    f"{table_name}_{self.definition}"
                    f"_{cmd_value}_policy_{self._policy_suffix}".lower()
                )

            self._policy_names.append(policy_name)

            generated_policy = utils.generate_rls_policy(
                cmd=cmd_value,
                definition=self.definition,
                policy_name=policy_name,
                table_name=table_name,
                expr=self._expr,
            )
            policy_lists.append(generated_policy)
        return policy_lists

    def __eq__(self, other):
        from . import utils

        if not isinstance(other, Policy):
            return NotImplemented

        definition_check = self.definition == other.definition
        cmd_check = self.cmd == other.cmd
        expression_check = utils.compare_between_policy_sql_expressions(
            self.expression, other.expression
        )

        return definition_check and cmd_check and expression_check

    def __str__(self):
        return f"Policy(definition={self.definition}, cmd={self.cmd}, expression={self.expression})"


class Permissive(Policy):
    definition: Literal["PERMISSIVE"] = "PERMISSIVE"


class Restrictive(Policy):
    definition: Literal["RESTRICTIVE"] = "RESTRICTIVE"
