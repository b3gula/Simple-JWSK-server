"""
Unit tests for the JWKS Server application.
Covers endpoint responses, registration, and rate limiting.
"""
import unittest
import time
from main import app, limiter
import database

class TestJWKSServer(unittest.TestCase):
    """Test cases for the main Flask application endpoints."""

    @classmethod
    def setUpClass(cls):
        """Ensure the database is initialized before any tests run."""
        database.init_db()

    def setUp(self):
        """Set up the test client before each test."""
        self.client = app.test_client()
        limiter.data.clear()

    def test_jwks_endpoint(self):
        """Test that the JWKS endpoint returns a 200 status."""
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json)

    def test_auth_endpoint(self):
        """Test that the standard auth endpoint returns a 200 status code."""
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 200)

    def test_expired_auth(self):
        """Test that the expired auth endpoint returns a 200 status code."""
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)

    def test_register_user(self):
        """Test the user registration endpoint."""
        test_username = f"testuser_{time.time()}"
        test_email = f"test_{time.time()}@test.com"
        
        response = self.client.post('/register', json={"username": test_username, "email": test_email})
        self.assertIn(response.status_code, [200, 201])
        self.assertIn('password', response.json)

        duplicate_response = self.client.post('/register', json={"username": test_username, "email": test_email})
        self.assertEqual(duplicate_response.status_code, 409)

    def test_rate_limiter(self):
        """Test that the rate limiter blocks after 10 requests within 1 second."""
        for _ in range(10):
            resp = self.client.post('/auth')
            self.assertEqual(resp.status_code, 200)

        blocked_resp = self.client.post('/auth')
        self.assertEqual(blocked_resp.status_code, 429)

if __name__ == '__main__':
    unittest.main()