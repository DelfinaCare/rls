from .setup import setup_database, teardown_database
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from typing import List, Any
from .engines import sync_engine, admin_engine
import pytest
import requests


session = sessionmaker(bind=sync_engine)()

admin_session = sessionmaker(bind=admin_engine)()


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
        "expr": "((owner_id = (NULLIF(current_setting('rls.items1_owner_id_condition_0_policy_0'::text, true), ''::text))::integer) AND ((title)::text = NULLIF(current_setting('rls.items1_title_condition_1_policy_0'::text, true), ''::text)))",
    },
]


@pytest.fixture(scope="session", autouse=True)
def setup_all_tests():
    teardown_database()

    setup_database()

    admin_session.execute(
        text("""
        INSERT INTO users (username) VALUES
        ('user1'),
        ('user2')
    """)
    )

    # Add Items
    admin_session.execute(
        text("""
        INSERT INTO items (title, description, owner_id) VALUES
        ('Item 1 for User 1', 'Description for Item 1', 1),
        ('Item 2 for User 1', 'Description for Item 2', 1),
        ('Item 1 for User 2', 'Description for Item 1', 2),
        ('Item 2 for User 2', 'Description for Item 2', 2)
    """)
    )

    admin_session.execute(
        text("""
        INSERT INTO items1 (title, description, owner_id) VALUES
        ('Item 1 for User 1', 'Description for Item 1', 1),
        ('Item 2 for User 1', 'Description for Item 2', 1),
        ('Item 1 for User 2', 'Description for Item 1', 2),
        ('Item 2 for User 2', 'Description for Item 2', 2)
    """)
    )

    admin_session.execute(
        text("""
        INSERT INTO items2 (title, description, owner_id) VALUES
        ('Item 1 for User 1', 'Description for Item 1', 1),
        ('Item 2 for User 1', 'Description for Item 2', 1),
        ('Item 1 for User 2', 'Description for Item 1', 2),
        ('Item 2 for User 2', 'Description for Item 2', 2)
    """)
    )

    admin_session.commit()

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

    # Make the request to get items for user with ID 1
    response = requests.get(
        "http://localhost:8000/users/items/1",
        headers={"Authorization": f"Bearer {token}"},
    )

    # Assert that the response status is 200 OK
    assert response.status_code == 200

    # Parse the response JSON
    res = response.json()

    # Fetch expected results from the database
    expected_res = admin_session.execute(
        text("SELECT * FROM items WHERE owner_id > 1")
    ).fetchall()

    # Ensure the number of items returned matches
    assert len(res) == len(expected_res)

    # Validate each item in the response against expected results
    for idx, item in enumerate(res):
        expected_item = expected_res[idx]._asdict()

        assert item["id"] == expected_item["id"]
        assert item["title"] == expected_item["title"]
        assert item["description"] == expected_item["description"]
        assert item["owner_id"] == expected_item["owner_id"]


def test_header_mode_normal_expr():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidGl0bGUiOiJpdGVtNDUiLCJkZXNjcmlwdGlvbiI6IkRlc2NyaXB0aW9uIGZvciBpdGVtNCIsImlhdCI6MTUxNjIzOTAyMn0.YfoupBUv7ydx6Btj13NqafJ3hXhN7m6mma9QZJ_6lWs"

    # Make the request to get items for user with ID 1
    response = requests.get(
        "http://localhost:8000/users/items/2",
        headers={"Authorization": f"Bearer {token}", "title": "Item 1 for User 1"},
    )

    # Assert that the response status is 200 OK
    assert response.status_code == 200

    # Parse the response JSON
    res = response.json()

    # Fetch expected results from the database
    expected_res = admin_session.execute(
        text("SELECT * FROM items WHERE owner_id = 1 AND title = 'Item 1 for User 1'")
    ).fetchall()

    # Ensure the number of items returned matches
    assert len(res) == len(expected_res)

    # Validate each item in the response against expected results
    for idx, item in enumerate(res):
        expected_item = expected_res[idx]._asdict()

        assert item["id"] == expected_item["id"]
        assert item["title"] == expected_item["title"]
        assert item["description"] == expected_item["description"]
        assert item["owner_id"] == expected_item["owner_id"]
