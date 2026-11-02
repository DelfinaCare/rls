EXPECTED_POLICIES = [
    {
        "tablename": "users",
        "policyname": "permissive_account_id_all_0sfb1v9p",
        "permissive": "PERMISSIVE",
        "cmd": "ALL",
        "qual": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "tablename": "items",
        "policyname": "permissive_account_id_all_g0sqhvhd",
        "permissive": "PERMISSIVE",
        "cmd": "ALL",
        "qual": "((owner_id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "tablename": "items",
        "policyname": "permissive_account_id_select_4j5d0vtn",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((owner_id > (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "tablename": "items",
        "policyname": "permissive_account_id_all_4g5q2zmb",
        "permissive": "PERMISSIVE",
        "cmd": "ALL",
        "qual": "((owner_id <= (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
]
