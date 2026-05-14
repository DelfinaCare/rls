import re

import sqlalchemy


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
        first_expression (str): The first SQL expression.
        second_expression (str): The second SQL expression.

    Returns:
        bool: True if the expressions are equivalent, False otherwise.
    """
    normalized_expr1 = normalize_sql_policy_expression(first_expression)
    normalized_expr2 = normalize_sql_policy_expression(second_expression)

    return normalized_expr1 == normalized_expr2
