import unittest
import time
from main import app, rate_limit_data
import database

class TestJWKSServer(unittest.TestCase):
    """Test cases for the main Flask application endpoints."""

    @classmethod
    def setUpClass(cls):
        database.init_db()

    def setUp(self):
        self.client = app.test_client()
        # Clear rate limit data between tests to avoid interference
        rate_limit_data.clear()

    def test_jwks_endpoint(self):
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json)

    def test_auth_endpoint(self):
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 200)

    def test_expired_auth(self):
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)

    def test_register_user(self):
        test_username = f"testuser_{time.time()}"
        test_email = f"test_{time.time()}@test.com"
        
        response = self.client.post('/register', json={"username": test_username, "email": test_email})
        self.assertIn(response.status_code, [200, 201])
        self.assertIn('password', response.json)

        # Test duplicate user rejection
        duplicate_response = self.client.post('/register', json={"username": test_username, "email": test_email})
        self.assertEqual(duplicate_response.status_code, 409)

    def test_rate_limiter(self):
        for _ in range(10):
            resp = self.client.post('/auth')
            self.assertEqual(resp.status_code, 200)

        # 11th request should be blocked (HTTP 429)
        blocked_resp = self.client.post('/auth')
        self.assertEqual(blocked_resp.status_code, 429)

if __name__ == '__main__':
    unittest.main()