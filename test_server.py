import unittest
import os
from main import app, init_db, DB_FILE

class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #Ensure the database is initialized before any tests run
        init_db()

    def setUp(self):
        self.client = app.test_client()

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

if __name__ == '__main__':
    unittest.main()