import inspect
from enum import Enum
from typing import Callable, List, Literal, Optional, Type, Union

from pydantic import BaseModel
from sqlalchemy import Boolean
from sqlalchemy.sql import func, sqltypes
from sqlalchemy.sql.elements import (
    ClauseElement,
)


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class ConditionArg(BaseModel):
    comparator_name: str
    type: Type[sqltypes.TypeEngine]


class Policy(BaseModel):
    definition: str
    condition_args: Optional[List[ConditionArg]] = None
    cmd: Union[Command, List[Command]]
    custom_expr: Optional[Callable[..., ClauseElement]] = None
    custom_policy_name: Optional[str] = None

    __policy_names: List[str] = []
    __compiled_custom_expr: ClauseElement = None
    __expr: str = ""
    __policy_suffix: str = ""
    __condition_args_prefix: str = "rls"

    class Config:
        arbitrary_types_allowed = True

    @property
    def policy_names(self) -> list[str]:
        """Getter for the private __policy_name field."""
        return self.__policy_names

    @property
    def expression(self) -> str:
        """Getter for the private __expr field."""
        return self.__expr

    @expression.setter
    def expression(self, expr: str) -> None:
        self.__expr = expr

    def _ensure_boolean(self):
        """
        Ensures that the given expression evaluates to a Boolean value.
        If not, it casts the expression to Boolean.
        """
        # Check if the expression is already of Boolean type
        if isinstance(self.__compiled_custom_expr.type, Boolean):
            return True

        # Otherwise, cast the expression to Boolean explicitly or raise an error
        raise ValueError("Expression does not evaluate to a Boolean value")
        # return expression.cast(Boolean)

    def _validate_Arguments_length(self):
        condition_args_length = (
            len(self.condition_args) if self.condition_args is not None else 0
        )
        lamda_args_length = len(inspect.signature(self.custom_expr).parameters)
        if condition_args_length != lamda_args_length:
            raise ValueError(
                f"Length mismatch for arguments. Expected {condition_args_length}, got {lamda_args_length}"
            )
        return True

    def _convert_lambda_to_clause_element(self):
        """Convert the lambda function to a SQLAlchemy expression."""
        args = []
        for arg in self.condition_args:
            coalesced_value = func.coalesce(
                func.current_setting(
                    f"{self.__condition_args_prefix}.{arg.comparator_name}"
                ),
                "",
            ).cast(arg.type)
            args.append(coalesced_value)
        self.__compiled_custom_expr = self.custom_expr(*args)
        self.__expr = str(
            self.__compiled_custom_expr.compile(compile_kwargs={"literal_binds": True})
        )

    def _get_expr_from_custom_expr(self, table_name: str):
        """Get the SQL expression from the custom expression with RLS prefixing."""
        if self.custom_expr is not None:
            self._validate_Arguments_length()

            self._convert_lambda_to_clause_element()

            self._ensure_boolean()
        else:
            raise ValueError(
                f"`custom_expr` must be defined for table `{table_name}`. If you're constructing expressions dynamically, "
            )

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        from .utils import generate_rls_policy

        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd
        self.__policy_suffix = name_suffix

        self._get_expr_from_custom_expr(table_name=table_name)

        policy_lists = []

        for cmd in commands:
            cmd_value = cmd.value if isinstance(cmd, Command) else cmd

            policy_name = ""
            if self.custom_policy_name is not None:
                policy_name = (
                    f"{table_name}_{self.custom_policy_name}"
                    f"_{cmd_value}_policy_{self.__policy_suffix}".lower()
                )
            else:
                policy_name = (
                    f"{table_name}_{self.definition}"
                    f"_{cmd_value}_policy_{self.__policy_suffix}".lower()
                )

            self.__policy_names.append(policy_name)

            generated_policy = generate_rls_policy(
                cmd=cmd_value,
                definition=self.definition,
                policy_name=policy_name,
                table_name=table_name,
                expr=self.__expr,
            )
            policy_lists.append(generated_policy)
        return policy_lists

    def __eq__(self, other):
        from .utils import compare_between_policy_sql_expressions

        if not isinstance(other, Policy):
            return NotImplemented

        definition_check = self.definition == other.definition
        cmd_check = self.cmd == other.cmd
        expression_check = compare_between_policy_sql_expressions(
            self.expression, other.expression
        )

        return definition_check and cmd_check and expression_check

    def __str__(self):
        return f"Policy(definition={self.definition}, cmd={self.cmd}, expression={self.expression})"


class Permissive(Policy):
    definition: Literal["PERMISSIVE"] = "PERMISSIVE"


class Restrictive(Policy):
    definition: Literal["RESTRICTIVE"] = "RESTRICTIVE"
