import unittest

from fastapi import testclient

from test import fastapi_sample


class FastapiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = testclient.TestClient(fastapi_sample.app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        del cls.client

    def test_rls_query(self):
        response = self.client.get("/users", params={"account_id": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["user1"])

    def test_rls_query_with_bypass(self):
        response = self.client.get("/all_users", params={"account_id": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["user1", "user2"])


if __name__ == "__main__":
    unittest.main()
