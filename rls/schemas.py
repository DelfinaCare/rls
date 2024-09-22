from enum import Enum
from typing import List, Literal, Union, TypedDict

from pydantic import BaseModel
from sqlalchemy import text


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


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
    condition_args: ConditionArgs
    cmd: Union[Command, List[Command]]

    def get_db_var_name(self, table_name):
        return f"rls.{table_name}_{self.condition_args['column_name']}"

    def _get_expr_from_params(self, table_name: str):
        variable_name = f"NULLIF(current_setting('{self.get_db_var_name(table_name)}', true),'')::{self.condition_args['type'].value}"

        expr = None
        if self.condition_args["operation"] == "EQUALITY":
            expr = f"{self.condition_args['column_name']} = {variable_name}"

        if expr is None:
            raise ValueError(f"Unknown operation: {self.condition_args['operation']}")

        return expr

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd
        expr = self._get_expr_from_params(table_name)
        policy_lists = []
        print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        print(expr)
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
                        USING ({expr})
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
                        WITH CHECK ({expr})
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
