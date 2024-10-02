from sqlalchemy import text, TextClause


def generate_rls_policy(cmd, definition, policy_name, table_name, expr) -> TextClause:
    bypass_rls_expr = (
        "CAST(NULLIF(current_setting('rls.bypass_rls', true), '') AS BOOLEAN) = true"
    )
    expr = f"(({expr}) OR {bypass_rls_expr})"
    if cmd in ["ALL", "SELECT", "UPDATE", "DELETE"]:
        return text(f"""
                CREATE POLICY {policy_name} ON {table_name}
                AS {definition}
                FOR {cmd}
                USING ({expr})
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
