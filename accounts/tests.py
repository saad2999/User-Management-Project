from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from .models import User


class UserManagementTests(APITestCase):

    def setUp(self):
        # Create admin, moderator, and simple users
        self.admin_user = User.objects.create_superuser(email="admin@example.com", name="Admin User", password="adminpass")
        self.moderator_user = User.objects.create_Moderator(email="moderator@example.com", name="Moderator User", password="modpass")
        self.simple_user = User.objects.create_user(email="user@example.com", name="Simple User", password="userpass")
        
        self.login_url = reverse('login')
        self.register_url = reverse('register')
        self.admin_register_url = reverse('admin-register')
        self.moderator_register_url = reverse('moderator-register')
        self.change_password_url = reverse('changepassword')
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

        self.assertEqual(response.data['email'], "newadmin@example.com")

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

        self.assertEqual(response.data['email'], "newuser@example.com")

    # 3. Test Login Success
    def test_user_login(self):
        data = {
            "email": "user@example.com",
            "password": "userpass"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if 'data' field is present in the response
        self.assertIn('data', response.data)

        # Check if 'token' field is present in the 'data'
        self.assertIn('token', response.data['data'])
        
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
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
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
        response = self.client.delete(reverse('delete-user', kwargs={'id': user_id}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # 10. Test Password Reset Email Sending
    def test_send_password_reset_email(self):
        data = {"email": "user@example.com"}
        response = self.client.post(self.send_reset_email_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('email', response.data)

    # 11. Test Password Reset Token (Valid Case)
    def test_password_reset_valid(self):
        uidb64 = "test_uid"
        token = "test_token"
        reset_url = reverse('password_reset', kwargs={'uidb64': uidb64, 'token': token})
        data = {
            "password": "newpass123",
            "password2": "newpass123"
        }
        response = self.client.post(reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # 12. Test Throttling on Login
    def test_login_throttling(self):
        data = {"email": "user@example.com", "password": "wrongpass"}
        for _ in range(4):  # 3 allowed, 4th should trigger throttling
            response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
