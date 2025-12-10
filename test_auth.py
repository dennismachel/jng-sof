import os
import unittest
from app import app

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        # Use test credentials and environment variables
        os.environ['POSTGRES_DB'] = 'statement_of_affairs'
        os.environ['POSTGRES_USER'] = 'testuser'
        os.environ['POSTGRES_PASSWORD'] = 'testpassword'
        os.environ['POSTGRES_HOST'] = 'localhost'
        os.environ['POSTGRES_PORT'] = '5432'

    def test_register_valid(self):
        response = self.client.post('/register', data={
            'email': 'test@jngroup.com',
            'password': 'TestPassword123'
        }, follow_redirects=True)
        self.assertIn(b'form', response.data)
        self.assertEqual(response.status_code, 200)

    def test_register_invalid_domain(self):
        response = self.client.post('/register', data={
            'email': 'bad@other.com',
            'password': 'TestPassword123'
        })
        self.assertIn(b'Invalid email format', response.data)

    def test_register_short_password(self):
        response = self.client.post('/register', data={
            'email': 'test2@jngroup.com',
            'password': 'short'
        })
        self.assertIn(b'Password must be at least 8 characters', response.data)

    def test_login_valid(self):
        # Register first
        self.client.post('/register', data={
            'email': 'login@jngroup.com',
            'password': 'ValidPassword123'
        })
        # Then login
        response = self.client.post('/login', data={
            'email': 'login@jngroup.com',
            'password': 'ValidPassword123'
        }, follow_redirects=True)
        self.assertIn(b'form', response.data)
        self.assertEqual(response.status_code, 200)

    def test_login_invalid(self):
        response = self.client.post('/login', data={
            'email': 'notfound@jngroup.com',
            'password': 'WrongPassword'
        })
        self.assertIn(b'Email and password do not match', response.data)

if __name__ == '__main__':
    unittest.main()
