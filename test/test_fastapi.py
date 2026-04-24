import asyncio
import unittest

import httpx
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


class FastapiAsyncTest(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_requests(self):
        n = 25
        barrier = asyncio.Barrier(n * 3)

        async def make_request(client, path, params, expected):
            await barrier.wait()
            response = await client.get(path, params=params)
            return response.status_code, response.json(), expected

        async with fastapi_sample.sample_database_setup(fastapi_sample.app):
            transport = httpx.ASGITransport(app=fastapi_sample.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                timeout=5.0,
            ) as client:
                tasks = []
                for _ in range(n):
                    tasks.append(
                        make_request(client, "/users", {"account_id": 1}, ["user1"])
                    )
                for _ in range(n):
                    tasks.append(
                        make_request(client, "/users", {"account_id": 2}, ["user2"])
                    )
                for _ in range(n):
                    tasks.append(
                        make_request(client, "/all_users", None, ["user1", "user2"])
                    )
                results = await asyncio.gather(*tasks)

        for status_code, body, expected in results:
            self.assertEqual(status_code, 200)
            self.assertEqual(body, expected)


if __name__ == "__main__":
    unittest.main()
