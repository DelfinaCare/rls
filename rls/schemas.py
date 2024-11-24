from enum import Enum
from typing import List, Literal, Union, TypedDict, Type

from pydantic import BaseModel
from .utils import generate_rls_policy
from sqlalchemy.sql.elements import (
    ClauseElement,
    BinaryExpression,
    UnaryExpression,
    BindParameter,
)
from sqlalchemy import Boolean, String
from sqlalchemy.sql import func, sqltypes, functions
from sqlalchemy.sql.sqltypes import NullType


class Command(str, Enum):
    # policies: https://www.postgresql.org/docs/current/sql-createpolicy.html
    all = "ALL"
    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class ConditionArgs(TypedDict):
    comparator_name: str
    type: Type[sqltypes.TypeEngine]


class Policy(BaseModel):
    definition: str
    condition_args: List[ConditionArgs]
    cmd: Union[Command, List[Command]]
    custom_expr: ClauseElement

    __policy_names: List[str] = []
    __expr: str = ""
    __policy_suffix: str = ""
    __condition_args_prefix: str = "rls"

    class Config:
        arbitrary_types_allowed = True

    def _add_null_safety_to_current_setting(self, expression: ClauseElement):
        """
        Recursively adds null safety to `func.current_setting` calls in SQLAlchemy expressions.
        Preserves correct type casting and avoids redundant casts.
        """

        def _safe_current_setting(expr):
            # Special handling for current_setting functions
            if isinstance(expr, functions.Function) and expr.name == "current_setting":
                # If the current_setting has a type (from cast), wrap with coalesce
                if hasattr(expr, "type") and not isinstance(expr.type, NullType):
                    # Return coalesce with the original type
                    return func.coalesce(expr, None).cast(expr.type)
                return func.coalesce(expr, None)

            # Handle type casting carefully
            if hasattr(expr, "type") and hasattr(expr, "clause"):
                # If it's a cast expression, safely transform the inner clause
                safe_clause = _safe_current_setting(expr.clause)
                return (
                    safe_clause.cast(expr.type)
                    if not isinstance(expr.type, NullType)
                    else safe_clause
                )

            # Recursive handling for binary expressions (like and_, or_)
            if hasattr(expr, "left") and hasattr(expr, "right"):
                expr.left = _safe_current_setting(expr.left)
                expr.right = _safe_current_setting(expr.right)

            # Handle lists of clauses (e.g., in or_ or and_)
            if hasattr(expr, "clauses"):
                expr.clauses = [
                    _safe_current_setting(clause) for clause in expr.clauses
                ]

            # Handle single clause
            if hasattr(expr, "clause"):
                expr.clause = _safe_current_setting(expr.clause)

            # Handle unary expressions
            if hasattr(expr, "element"):
                expr.element = _safe_current_setting(expr.element)

            return expr

        return _safe_current_setting(expression)

    def _extract_current_setting_arguments_with_types(self, expression: ClauseElement):
        """
        Recursively extract arguments and their types passed to `func.current_setting` in any SQLAlchemy ClauseElement.
        If no type is found, default to `String`.
        """
        extracted = []

        # Handle BinaryExpression (e.g., col == value)
        if isinstance(expression, BinaryExpression):
            extracted.extend(
                self._extract_current_setting_arguments_with_types(expression.left)
            )
            extracted.extend(
                self._extract_current_setting_arguments_with_types(expression.right)
            )

        # Handle UnaryExpression (e.g., NOT, IS NULL, etc.)
        elif isinstance(expression, UnaryExpression):
            extracted.extend(
                self._extract_current_setting_arguments_with_types(expression.element)
            )

        # Handle functions (e.g., func.current_setting())
        # Base Case
        elif isinstance(expression, functions.Function):
            if expression.name == "current_setting":  # Check if it's `current_setting`
                for clause in expression.clauses:
                    if isinstance(clause, BindParameter) and isinstance(
                        clause.value, str
                    ):
                        # Include the type from `.cast()` if available, otherwise default to String

                        extracted.append(
                            (
                                clause.value,
                                type(expression.type)
                                if not isinstance(expression.type, NullType)
                                else String,
                            )
                        )
            else:  # Recurse into other functions
                for clause in expression.clauses:
                    extracted.extend(
                        self._extract_current_setting_arguments_with_types(clause)
                    )

        # Handle Cast explicitly
        elif hasattr(expression, "clause") and hasattr(expression, "type"):
            # Extract the argument and its cast type
            sub_results = self._extract_current_setting_arguments_with_types(
                expression.clause
            )
            for result in sub_results:
                extracted.append(
                    (
                        result[0],
                        type(expression.type)
                        if not isinstance(expression.type, NullType)
                        else String,
                    )
                )  # Use cast type or default to String

        # Handle generic ClauseElement with 'clauses'
        elif hasattr(expression, "clauses"):
            for clause in expression.clauses:
                extracted.extend(
                    self._extract_current_setting_arguments_with_types(clause)
                )

        # Handle other possible elements (e.g., Label, TypeClause, etc.)
        elif hasattr(expression, "element"):
            extracted.extend(
                self._extract_current_setting_arguments_with_types(expression.element)
            )

        return extracted

    def _add_prefix_to_current_settings_vars(
        self, expression: ClauseElement, prefix: str
    ):
        """
        Recursively adds a prefix to `func.current_setting` calls in SQLAlchemy expressions.
        Preserves correct type casting and handles binary and unary expressions.
        """

        def _add_prefix(expr):
            # Special handling for `current_setting` functions
            if isinstance(expr, functions.Function) and expr.name == "current_setting":
                # Modify the first argument (setting name) to include the prefix directly
                if hasattr(expr, "clauses") and len(expr.clauses.clauses) > 0:
                    setting_name_clause = expr.clauses.clauses[0]
                    # Check if the clause is a `BindParameter` (typically holds the setting name)
                    if isinstance(setting_name_clause, BindParameter):
                        # Prevent duplicate prefixing
                        if not setting_name_clause.value.startswith(prefix):
                            prefixed_setting_name = f"{prefix}.{setting_name_clause.value}"  # Add the prefix
                            expr.clauses.clauses[0] = BindParameter(
                                None, prefixed_setting_name
                            )  # Replace safely
                    else:
                        raise ValueError(
                            "Unsupported clause type for current_setting argument: "
                            f"{type(setting_name_clause)}"
                        )
                return expr

            # Handle type casting carefully
            if hasattr(expr, "type") and hasattr(expr, "clause"):
                # If it's a cast expression, transform the inner clause
                prefixed_clause = _add_prefix(expr.clause)
                return prefixed_clause.cast(expr.type) if expr.type else prefixed_clause

            # Recursive handling for binary expressions (like ==, !=, and_, or_)
            if hasattr(expr, "left") and hasattr(expr, "right"):
                expr.left = _add_prefix(expr.left)
                expr.right = _add_prefix(expr.right)

            # Handle unary expressions (e.g., negation or functions like `not_`)
            if hasattr(expr, "element"):
                expr.element = _add_prefix(expr.element)

            # Handle lists of clauses (e.g., in or_ or and_)
            if hasattr(expr, "clauses"):
                expr.clauses = [_add_prefix(clause) for clause in expr.clauses]

            # Handle single clause
            if hasattr(expr, "clause"):
                expr.clause = _add_prefix(expr.clause)

            return expr

        return _add_prefix(expression)

    def _ensure_boolean(self, expression: ClauseElement):
        """
        Ensures that the given expression evaluates to a Boolean value.
        If not, it casts the expression to Boolean.
        """
        # Check if the expression is already of Boolean type
        if isinstance(expression.type, Boolean):
            return expression

        # Otherwise, cast the expression to Boolean explicitly or raise an error
        raise ValueError("Expression does not evaluate to a Boolean value")
        # return expression.cast(Boolean)

    def _validate_expression_with_conditional_args(self, expression: ClauseElement):
        current_setting_args = self._extract_current_setting_arguments_with_types(
            expression
        )

        for arg, arg_type in current_setting_args:
            for cond_arg in self.condition_args:
                if arg == cond_arg["comparator_name"] and arg_type == cond_arg["type"]:
                    cond_arg["found"] = True
                    return True

        for cond_arg in self.condition_args:
            if not cond_arg.get("found", False):
                raise ValueError(
                    f"Expected argument '{cond_arg['comparator_name']}' with type '{cond_arg['type']}' in expression but it was not found"
                )

        return False

    def _get_expr_from_custom_expr(self, table_name: str):
        """Get the SQL expression from the custom expression with RLS prefixing."""
        if isinstance(self.custom_expr, ClauseElement):
            validation_status = self._validate_expression_with_conditional_args(
                expression=self.custom_expr
            )
            print("Validation status:", validation_status)

            ensured_boolean_expr = self._ensure_boolean(expression=self.custom_expr)
            print(
                "Ensured expression:",
                str(
                    ensured_boolean_expr.compile(compile_kwargs={"literal_binds": True})
                ),
            )

            prefixed_expr = self._add_prefix_to_current_settings_vars(
                expression=ensured_boolean_expr, prefix=self.__condition_args_prefix
            )
            print(
                "Prefixed expression:",
                str(prefixed_expr.compile(compile_kwargs={"literal_binds": True})),
            )

            safe_expr = self._add_null_safety_to_current_setting(
                expression=prefixed_expr
            )
            print(
                "Safe expression:",
                str(safe_expr.compile(compile_kwargs={"literal_binds": True})),
            )

            return str(safe_expr.compile(compile_kwargs={"literal_binds": True}))

        raise ValueError(
            f"`custom_expr` must be defined for table `{table_name}`. If you're constructing expressions dynamically, "
        )

    @property
    def policy_names(self) -> list[str]:
        """Getter for the private __policy_name field."""
        return self.__policy_names

    @property
    def expression(self) -> str:
        """Getter for the private __expr field."""
        return self.__expr

    def get_sql_policies(self, table_name: str, name_suffix: str = "0"):
        commands = [self.cmd] if isinstance(self.cmd, str) else self.cmd
        self.__policy_suffix = name_suffix

        self.__expr = self._get_expr_from_custom_expr(table_name=table_name)

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
