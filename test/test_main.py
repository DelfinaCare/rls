from .main import app
from .setup import setup_database, teardown_database
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from typing import List, Any
from .engines import sync_engine
import pytest

client = TestClient(app)


session = sessionmaker(bind=sync_engine)()


policies: List[Any] = [
    {
        "policy_name": "items_permissive_all_policy_0",
        "expr": "(owner_id > (NULLIF(current_setting('rls.items_sub_bearer_token_payload_condition_0_policy_0'::text, true), ''::text))::integer)",
    },
    {
        "policy_name": "items2_permissive_select_policy_0",
        "expr": "(owner_id = (NULLIF(current_setting('rls.items2_owner_id_condition_0_policy_0'::text, true), ''::text))::integer)",
    },
    {
        "policy_name": "items1_permissive_all_policy_0",
        "expr": "((owner_id = (NULLIF(current_setting('rls.items1_owner_id_condition_0_policy_0'::text, true), ''::text))::integer) AND (((title)::text = NULLIF(current_setting('rls.items1_title_condition_1_policy_0'::text, true), ''::text)) OR ((description)::text = NULLIF(current_setting('rls.items1_description_condition_2_policy_0'::text, true), ''::text))))",
    },
]


@pytest.fixture(scope="session", autouse=True)
def setup_all_tests():
    teardown_database()

    setup_database()

    print("Finished setting up before all tests...")


def test_policy_creation():
    res = session.execute(text("select * from pg_policies"))
    result = res.fetchall()
    for row in result:
        row_dict = row._asdict()

        policy_name = row_dict["policyname"]
        policy_expr = row_dict["qual"]

        assertion_flag = False

        for policy in policies:
            if policy_name == policy["policy_name"]:
                assert policy_expr == policy["expr"]
                assertion_flag = True
                break

        if not assertion_flag:
            assert False


def test_bearer_token_mode_normal_expr():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidGl0bGUiOiJpdGVtNDUiLCJkZXNjcmlwdGlvbiI6IkRlc2NyaXB0aW9uIGZvciBpdGVtNCIsImlhdCI6MTUxNjIzOTAyMn0.YfoupBUv7ydx6Btj13NqafJ3hXhN7m6mma9QZJ_6lWs"
    response = client.get(
        "/users/items/1", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    print("&&&&&&&&&&&&&&&&&&&&")
    print(response.json())
    print("&&&&&&&&&&&&&&&&&&&&")

    # Step 1: Make the request
    pass


def test_header_mode_normal_expr():
    # Step 1: Make the request
    pass


def test_request_user_mode_normal_expr():
    # Step 1: Make the request
    pass


def test_bearer_token_mode_joined_expr():
    # Step 1: Make the request
    pass


def test_header_mode_joined_expr():
    # Step 1: Make the request
    pass


def test_request_user_mode_joined_expr():
    # Step 1: Make the request
    pass


def test_bearer_token_mode_custom_expr():
    # Step 1: Make the request
    pass


def test_header_mode_custom_expr():
    # Step 1: Make the request
    pass


def test_request_user_mode_custom_expr():
    # Step 1: Make the request
    pass
