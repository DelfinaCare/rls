import concurrent.futures
import threading
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

    def test_concurrent_requests(self):
        total = 75
        barrier = threading.Barrier(total)

        def make_request(path, params, expected):
            barrier.wait()
            response = self.client.get(path, params=params)
            return response.status_code, response.json(), expected

        with concurrent.futures.ThreadPoolExecutor(max_workers=total) as executor:
            futures = []
            for _ in range(25):
                futures.append(
                    executor.submit(
                        make_request, "/users", {"account_id": 1}, ["user1"]
                    )
                )
            for _ in range(25):
                futures.append(
                    executor.submit(
                        make_request, "/users", {"account_id": 2}, ["user2"]
                    )
                )
            for _ in range(25):
                futures.append(
                    executor.submit(
                        make_request,
                        "/all_users",
                        None,
                        ["user1", "user2"],
                    )
                )

            for future in concurrent.futures.as_completed(futures):
                status_code, body, expected = future.result()
                self.assertEqual(status_code, 200)
                self.assertEqual(body, expected)


if __name__ == "__main__":
    unittest.main()
