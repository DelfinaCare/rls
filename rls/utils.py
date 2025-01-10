import re

from sqlalchemy import TextClause, text

from .schemas import Command, Policy


def add_bypass_rls_to_expr(expr: str) -> str:
    bypass_rls_expr = (
        "CAST(NULLIF(current_setting('rls.bypass_rls', true), '') AS BOOLEAN) = true"
    )
    return f"(({expr}) OR {bypass_rls_expr})"


def generate_rls_policy(
    cmd: str, definition: str, policy_name: str, table_name: str, expr: str
) -> TextClause:
    if "rls.bypass_rls" not in expr:
        expr = add_bypass_rls_to_expr(expr)

    if cmd in ["ALL", "SELECT", "DELETE"]:
        return text(f"""
                CREATE POLICY {policy_name} ON {table_name}
                AS {definition}
                FOR {cmd}
                USING ({expr})
                """)

    elif cmd == "UPDATE":
        # UPDATE requires both USING and WITH CHECK
        return text(f"""
            CREATE POLICY {policy_name} ON {table_name}
            AS {definition}
            FOR {cmd}
            USING ({expr})
            WITH CHECK ({expr});
        """)

    elif cmd in ["INSERT"]:
        return text(f"""
                CREATE POLICY {policy_name} ON {table_name}
                AS {definition}
                FOR {cmd}
                WITH CHECK ({expr})
                """)

    else:
        raise ValueError(f'Unknown policy command"{cmd}"')


def policy_changed_checker(db_policy: Policy, metadata_policy: Policy) -> bool:
    temp_metadata_policy = metadata_policy.model_copy()
    temp_metadata_policy.expression = add_bypass_rls_to_expr(metadata_policy.expression)

    if isinstance(temp_metadata_policy.cmd, list):
        temp_metadata_policy.cmd = Command(temp_metadata_policy.cmd[0])

    return bool(db_policy == temp_metadata_policy)


def normalize_sql_policy_expression(expression: str) -> str:
    """
    Normalizes a SQL expression for comparison by:
    - Lowercasing all keywords.
    - Removing unnecessary whitespace.
    - Standardizing CAST syntax and other quirks.
    """

    # do the same thing sqlparse did but without sql parse
    parsed: str = expression.lower()

    # Remove any :: type casts with the type after it ( any word) \w+ like this
    parsed = re.sub(r"::\w+", "", parsed)

    # Remove as anyword from expression
    parsed = re.sub(r"as \w+", "", parsed)

    parsed = parsed.replace(" ", "")
    parsed = parsed.replace("(", "")
    parsed = parsed.replace(")", "")
    # Replace "CAST(... AS TYPE)" with "::type" for uniformity
    parsed = parsed.replace("cast", "")

    return parsed


def compare_between_policy_sql_expressions(
    first_expression: str, second_expression: str
) -> bool:
    """
    Compare two SQL expressions for equivalence by normalizing them.

    Args:
        expr1 (str): The first SQL expression.
        expr2 (str): The second SQL expression.

    Returns:
        bool: True if the expressions are equivalent, False otherwise.
    """
    # Normalize both expressions
    normalized_expr1 = normalize_sql_policy_expression(first_expression)
    normalized_expr2 = normalize_sql_policy_expression(second_expression)

    # Compare the normalized expressions
    return normalized_expr1 == normalized_expr2
