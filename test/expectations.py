EXPECTED_POLICIES = [
    {
        "policyname": "items_smaller_than_or_equal_accountid_policy_all_polic_7c6cc9a9",
        "permissive": "PERMISSIVE",
        "cmd": "ALL",
        "qual": "((owner_id <= (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_greater_than_accountid_policy_select_policy_1_74445056",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((owner_id > (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_equal_to_accountid_policy_update_policy_0_e24ed5f2",
        "permissive": "PERMISSIVE",
        "cmd": "UPDATE",
        "qual": "((owner_id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_equal_to_accountid_policy_select_policy_0_e78bd21e",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((owner_id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "users_equal_to_accountid_policy_update_policy_0_cd807a67",
        "permissive": "PERMISSIVE",
        "cmd": "UPDATE",
        "qual": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
        "with_check": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "users_equal_to_accountid_policy_select_policy_0_1305ed40",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
]
