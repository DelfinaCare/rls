EXPECTED_POLICIES = [
    {
        "policyname": "items_smaller_than_or_equal_accountid_policy_all_2_9t43113q",
        "permissive": "PERMISSIVE",
        "cmd": "ALL",
        "qual": "((owner_id <= (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_greater_than_accountid_policy_select_1_9jopmaj0",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((owner_id > (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_equal_to_accountid_policy_update_0_c8bumln9",
        "permissive": "PERMISSIVE",
        "cmd": "UPDATE",
        "qual": "((owner_id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "items_equal_to_accountid_policy_select_0_zhmjec78",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((owner_id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "users_equal_to_accountid_policy_update_0_k15qom6y",
        "permissive": "PERMISSIVE",
        "cmd": "UPDATE",
        "qual": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
        "with_check": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
    {
        "policyname": "users_equal_to_accountid_policy_select_0_gbvzb311",
        "permissive": "PERMISSIVE",
        "cmd": "SELECT",
        "qual": "((id = (NULLIF(current_setting('rls.account_id'::text, true), ''::text))::integer) OR ((NULLIF(current_setting('rls.bypass_rls'::text, true), ''::text))::boolean = true))",
    },
]
