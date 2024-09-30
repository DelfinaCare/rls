from enum import Enum
from typing import List, Literal, Union, TypedDict, Optional, NotRequired

from pydantic import BaseModel
from .utils import generate_rls_policy
from sqlalchemy.sql import sqltypes

import re


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class LogicalOperator(str, Enum):
    AND = "AND"
    OR = "OR"


class Operation(str, Enum):
    equality = "="
    inequality = "<>"
    greater_than = ">"
    greater_than_or_equal = ">="
    less_than = "<"
    less_than_or_equal = "<="
    like = "LIKE"


class ConditionArgs(TypedDict):
    comparator_name: str
    type: sqltypes
    operation: NotRequired[Optional[Operation]] = None
    column_name: NotRequired[Optional[str]] = None


class Policy(BaseModel):
    definition: str
    condition_args: List[ConditionArgs]
    cmd: Union[Command, List[Command]]
    joined_expr: Optional[str] = None
    custom_expr: Optional[str] = None

    __policy_names: List[str] = []
    __expr: str = None
    __policy_suffix: int = 0

    class Config:
        arbitrary_types_allowed = True

    def _get_safe_variable_name(self, idx: int = 0):
        type_str = self.condition_args[idx]["type"].__visit_name__.upper()
        return f"NULLIF(current_setting('rls.{self.condition_args[idx]["comparator_name"]}', true),'')::{type_str}"

    def _get_expr_from_params(self, table_name: str, idx: int = 0):
        safe_variable_name = self._get_safe_variable_name(idx=idx)

        expr = f"{self.condition_args[idx]['column_name']} {self.condition_args[idx]['operation'].value} {safe_variable_name}"

        return expr

    def _get_expr_from_joined_expr(self, table_name: str):
        expr = self.joined_expr
        for idx in range(len(self.condition_args)):
            pattern = rf"\{{{idx}\}}"  # Escaped curly braces
            parsed_expr = self._get_expr_from_params(table_name, idx)
            expr = re.sub(pattern, parsed_expr, expr)
        return expr

    def _get_expr_from_custom_expr(self, table_name: str):
        expr = self.custom_expr
        for idx in range(len(self.condition_args)):
            safe_variable_name = self._get_safe_variable_name(idx=idx)
            pattern = rf"\{{{idx}\}}"
            expr = re.sub(pattern, safe_variable_name, expr)
        return expr

    def _validate_joining_operations_in_expr(self):
        # Pattern to match a number in curly braces followed by "AND" or "OR"
        whole_pattern = r"\{(\d+)\}\s*(AND|OR)"

        # Find all matches of the pattern in the expression
        matches = re.findall(whole_pattern, self.expr)

        # Extract the second group (AND/OR) from each match
        operators = [match[1] for match in matches]

        for operator in operators:
            if operator not in LogicalOperator.__members__.values():
                raise ValueError(f"Invalid logical operator: {operator}")

    def _validate_state(self):
        for condition_arg in self.condition_args:
            if self.joined_expr is not None and (
                "column_name" not in condition_arg or "operation" not in condition_arg
            ):
                raise ValueError(
                    "condition_args must be provided if joined_expr is provided"
                )

            if self.custom_expr is not None:
                if "column_name" in condition_arg or "operation" in condition_arg:
                    raise ValueError(
                        "column name and operation must not be provided if custom_expr is provided"
                    )

                if (
                    "comparator_name" not in condition_arg
                    and "comparator_source" not in condition_arg
                    and "type" not in condition_arg
                    and re.search(r"\{(\d+)\}", self.custom_expr)
                ):
                    raise ValueError(
                        "comparator_name, comparator_source and type must be provided if custom_expr is provided with parameters"
                    )

    @property
    def policy_names(self) -> str:
        """Getter for the private __policy_name field."""
        return self.__policy_names

    @property
    def expression(self) -> str:
        """Getter for the private __expr field."""
        return self.__expr

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd
        self.__policy_suffix = name_suffix

        self._validate_state()

        if self.custom_expr is not None:
            self.__expr = self._get_expr_from_custom_expr(table_name)
        elif self.joined_expr is not None:
            self.__expr = self._get_expr_from_joined_expr(table_name)
        else:
            self.__expr = self._get_expr_from_params(table_name)

        policy_lists = []

        for cmd in commands:
            cmd_value = cmd.value if isinstance(cmd, Command) else cmd
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


class Permissive(Policy):
    definition: Literal["PERMISSIVE"] = "PERMISSIVE"


class Restrictive(Policy):
    definition: Literal["RESTRICTIVE"] = "RESTRICTIVE"
