import asyncio
import unittest

from fastapi import testclient

from test import fastapi_sample


class FastapiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Manually run the lifespan async generator for the test database setup
        loop = asyncio.get_event_loop()
        cls.lifespan = loop.run_until_complete(
            fastapi_sample.app.router.lifespan_context(fastapi_sample.app).__aenter__()
        )

        # Create a TestClient instance
        cls.client = testclient.TestClient(fastapi_sample.app)

    @classmethod
    def tearDownClass(cls):
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
