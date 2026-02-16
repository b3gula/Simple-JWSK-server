import unittest
from main import app

class TestJWKSServer(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_jwks_endpoint(self):
        response = self.client.get('/jwks')
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json)

    def test_auth_endpoint(self):
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 200)

    def test_expired_auth(self):
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()