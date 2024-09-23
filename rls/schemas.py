from enum import Enum
from typing import List, Literal, Union, TypedDict, Optional

from pydantic import BaseModel
from sqlalchemy import text

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
    equality = "EQUALITY"


class ExpressionTypes(str, Enum):
    integer = "INTEGER"
    uuid = "UUID"
    text = "TEXT"
    boolean = "BOOLEAN"


class ComparatorSource(str, Enum):
    header = "header"
    bearerTokenPayload = "bearer_token_payload"
    requestUser = "request_user"


class ConditionArgs(TypedDict):
    comparator_name: str
    comparator_source: ComparatorSource
    operation: Operation
    type: ExpressionTypes
    column_name: str


class Policy(BaseModel):
    definition: str
    condition_args: List[ConditionArgs]
    cmd: Union[Command, List[Command]]
    expr: Optional[str]

    def get_db_var_name(self, table_name: str, idx: int = 0):
        return f"rls.{table_name}_{self.condition_args[idx]['column_name']}"

    def _get_expr_from_params(self, table_name: str, idx: int = 0):
        variable_name = f"NULLIF(current_setting('{self.get_db_var_name(table_name=table_name, idx=idx)}', true),'')::{self.condition_args[idx]['type'].value}"

        expr = None
        if self.condition_args[idx]["operation"] == "EQUALITY":
            expr = f"{self.condition_args[idx]['column_name']} = {variable_name}"

        if expr is None:
            raise ValueError(
                f"Unknown operation: {self.condition_args[idx]['operation']}"
            )

        return expr

    def _get_expr_from_custom_expr(self, table_name: str):
        for idx in range(len(self.condition_args)):
            pattern = rf"\{{{idx}\}}"  # Escaped curly braces
            parsed_expr = self._get_expr_from_params(table_name, idx)
            self.expr = re.sub(pattern, parsed_expr, self.expr)
        return self.expr

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

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd

        if self.expr is not None:
            self.expr = self._get_expr_from_custom_expr(table_name)
        else:
            self.expr = self._get_expr_from_params(table_name)
        policy_lists = []
        print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        print(self.expr)
        print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")

        for cmd in commands:
            cmd_value = cmd.value if isinstance(cmd, Command) else cmd
            policy_name = (
                f"{table_name}_{self.definition}"
                f"_{cmd_value}_policy_{name_suffix}".lower()
            )

            if cmd_value in ["ALL", "SELECT", "UPDATE", "DELETE"]:
                policy_lists.append(
                    text(
                        f"""
                        CREATE POLICY {policy_name} ON {table_name}
                        AS {self.definition}
                        FOR {cmd_value}
                        USING ({self.expr})
                        """
                    )
                )
            elif cmd in ["INSERT"]:
                policy_lists.append(
                    text(
                        f"""
                        CREATE POLICY {policy_name} ON {table_name}
                        AS {self.definition}
                        FOR {cmd_value}
                        WITH CHECK ({self.expr})
                        """
                    )
                )
            else:
                raise ValueError(f'Unknown policy command"{cmd_value}"')
        return policy_lists


class Permissive(Policy):
    definition: Literal["PERMISSIVE"] = "PERMISSIVE"


class Restrictive(Policy):
    definition: Literal["RESTRICTIVE"] = "RESTRICTIVE"
