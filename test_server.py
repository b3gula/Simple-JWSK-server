"""
Unit tests for the JWKS Server application.
Extensive coverage for endpoints, database methods, and rate limiting edge cases.
"""
import unittest
import time
import base64
from main import app, limiter
import database

class TestJWKSServer(unittest.TestCase):
    """Extensive test cases covering successful, failed, and edge-case execution paths."""

    @classmethod
    def setUpClass(cls):
        """Ensure the database is initialized before any tests run."""
        database.init_db()

    def setUp(self):
        """Set up the test client before each test and clear the rate limiter."""
        self.client = app.test_client()
        limiter.data.clear()

    def test_health_check(self):
        """Coverage: Hits the base / endpoint."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint(self):
        """Coverage: Standard JWKS retrieval."""
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json)

    def test_auth_endpoint_no_data(self):
        """Coverage: Auth with no data provided."""
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 200)

    def test_auth_endpoint_json_data(self):
        """Coverage: Auth with JSON payload, tests user ID lookup."""
        test_user = f"json_user_{time.time()}"
        self.client.post('/register', json={"username": test_user, "email": f"{test_user}@test.com"})
        
        response = self.client.post('/auth', json={"username": test_user})
        self.assertEqual(response.status_code, 200)

    def test_auth_endpoint_basic_auth(self):
        """Coverage: Auth with HTTP Basic Auth headers."""
        test_user = f"basic_user_{time.time()}"
        self.client.post('/register', json={"username": test_user, "email": f"{test_user}@basic.com"})
        
        auth_string = f"{test_user}:password"
        auth_bytes = auth_string.encode('utf-8')
        auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')
        
        response = self.client.post('/auth', headers={'Authorization': f'Basic {auth_base64}'})
        self.assertEqual(response.status_code, 200)

    def test_expired_auth(self):
        """Coverage: Retrieve expired key JWT."""
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)

    def test_register_user_success_and_duplicate(self):
        """Coverage: Registration success (201) and duplicate collision (409)."""
        test_user = f"reg_user_{time.time()}"
        test_email = f"reg_{time.time()}@test.com"
        
        response = self.client.post('/register', json={"username": test_user, "email": test_email})
        self.assertIn(response.status_code, [200, 201])
        self.assertIn('password', response.json)

        duplicate_response = self.client.post('/register', json={"username": test_user, "email": test_email})
        self.assertEqual(duplicate_response.status_code, 409)

    def test_register_invalid_params(self):
        """Coverage: Registration with missing parameters (400)."""
        response = self.client.post('/register', json={"username_only": "fails"})
        self.assertEqual(response.status_code, 400)
        
        response_empty = self.client.post('/register')
        self.assertEqual(response_empty.status_code, 400)

    def test_rate_limiter(self):
        """Coverage: Exceeds rate limit to trigger 429 response."""
        for _ in range(10):
            resp = self.client.post('/auth')
            self.assertEqual(resp.status_code, 200)

        blocked_resp = self.client.post('/auth')
        self.assertEqual(blocked_resp.status_code, 429)

    # --- Direct Database Module Coverage Tests ---

    def test_db_get_user_not_found(self):
        """Coverage: db get_user with non-existent user."""
        result = database.get_user_by_username("this_user_does_not_exist_at_all")
        self.assertIsNone(result)

    def test_db_is_empty_false(self):
        """Coverage: is_db_empty should be false because of setUpClass."""
        self.assertFalse(database.is_db_empty())

    def test_db_save_and_retrieve_valid_keys(self):
        """Coverage: Save a key and retrieve valid keys directly."""
        # Using a dummy 32-byte string to simulate a PEM to hit specific DB logic branches
        dummy_pem = b"A" * 32
        database.save_key_to_db(dummy_pem, int(time.time()) + 10000)
        
        keys = database.get_valid_keys_from_db(int(time.time()))
        self.assertTrue(len(keys) > 0)

if __name__ == '__main__':
    unittest.main()