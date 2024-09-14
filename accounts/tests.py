from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from .models import User
from django.utils.encoding import force_bytes,smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
class UserManagementTests(APITestCase):

    def setUp(self):
        # Create admin, moderator, and simple users
        
        self.admin_user = User.objects.create_superuser(email="admin@example.com", name="Admin User", password="adminpass")
        self.moderator_user = User.objects.create_Moderator(email="moderator@example.com", name="Moderator User", password="modpass")
        self.simple_user = User.objects.create_user(email="user@example.com", name="Simple User", password="userpass")
        
        self.login_url = reverse('login')
        self.register_url = reverse('register')
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.simple_user.pk))  # Encode user ID

        self.admin_register_url = reverse('admin-register')
        self.moderator_register_url = reverse('moderator-register')
        self.change_password_url = reverse('changepassword')
        self.token = PasswordResetTokenGenerator().make_token(self.simple_user)  # Generate token for password reset

        self.profile_url = reverse('profile')
        self.send_reset_email_url = reverse('send-password-reset-email')

    # 1. Test Admin Registration
    def test_admin_registration(self):
        data = {
            "email": "newadmin@example.com",
            "name": "New Admin",
            "password": "newadminpass",
            "password2": "newadminpass"
        }
        response = self.client.post(self.admin_register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('token', response.data)
        self.assertIn('msg', response.data)
        self.assertEqual(response.data['msg'], "Admin Registration successful")

    # 2. Test User Registration
    def test_user_registration(self):
        data = {
            "email": "newuser@example.com",
            "name": "New User",
            "password": "userpass123",
            "password2": "userpass123"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('token', response.data)
        self.assertIn('msg', response.data)
        self.assertEqual(response.data['msg'], "User Registration successful")

    # 3. Test Login Success
    def test_user_login(self):
        data = {
            "email": "user@example.com",
            "password": "userpass"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertIn('token', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], "Login successful")

        # Check if 'data' field is present in the response
        self.assertIn('data', response.data)

        # Check if 'token' field is present in the 'data'
        self.assertIn('token', response.data['data'])
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        
        # Check if 'access' and 'refresh' tokens are present
        self.assertIn('access', response.data['data']['token'])
        self.assertIn('refresh', response.data['data']['token'])
    # 4. Test Login Failure
    def test_login_failure(self):
        data = {
            "email": "user@example.com",
            "password": "wrongpass"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)

    # 5. Test Profile Retrieval (Authenticated User)
    def test_profile_retrieval(self):
        self.client.force_authenticate(user=self.simple_user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'user@example.com')

    # 6. Test Profile Retrieval (Unauthenticated User)
    def test_profile_retrieval_unauthenticated(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # 7. Test Password Change (Authenticated User)
    def test_change_password(self):
        self.client.force_authenticate(user=self.simple_user)
        data = {
            "password": "newuserpass",
            "password2": "newuserpass"
        }
        response = self.client.post(self.change_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # 8. Test Delete User (Admin)
    def test_admin_can_delete_user(self):
        self.client.force_authenticate(user=self.admin_user)
        user_id = self.simple_user.id
        response = self.client.delete(reverse('delete-user', kwargs={'pk': user_id}))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    # 9. Test Delete User (Moderator Forbidden)
    def test_moderator_cannot_delete_user(self):
        self.client.force_authenticate(user=self.moderator_user)
        user_id = self.simple_user.id
        response = self.client.delete(reverse('delete-user', kwargs={'pk': user_id}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # 10. Test Password Reset Email Sending
    def test_send_password_reset_email(self):
        data = {"email": "saad586305@gmail.com"}
        response = self.client.post(self.send_reset_email_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('msg', response.data)
        self.assertEqual(response.data['msg'], 'Password reset email has been sent')
    # 11. Test Password Reset Token (Valid Case)
    def test_password_reset_valid(self):
        reset_url = reverse('user/password-reset/', kwargs={'uidb64': self.uidb64, 'token': self.token})
        data = {
            'password': 'new_password123',
            'password2': 'new_password123',
        }
        response = self.client.post(reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # 12. Test Throttling on Login
    def test_login_throttling(self):
        data = {"email": "user@example.com", "password": "wrongpass"}
        for _ in range(4):  # 3 allowed, 4th should trigger throttling
            response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
