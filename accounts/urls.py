from django.urls import path
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserProflieView,
    ChangeUserPasswordView,
    SendPasswordResetEmailView,
    UserPasswordResetView,
    AdminRegistrationView,
    UserUpdateView,
    UserDeleteView,
    ModeratorRegistrationView,
)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProflieView.as_view(), name='profile'),
    path('changepassword/', ChangeUserPasswordView.as_view(), name='changepassword'),
    path('send-password-reset-email/', SendPasswordResetEmailView.as_view(), name='send-password-reset-email'),
    path('user/reset-password/<str:uidb64>/<str:token>/', UserPasswordResetView.as_view(), name='password_reset'),
    path('admin-register/', AdminRegistrationView.as_view(), name='admin-register'),
    path('update-user/<int:pk>/', UserUpdateView.as_view(), name='update-user'),
    path('delete-user/<int:pk>/', UserDeleteView.as_view(), name='delete-user'),
    path('moderator-register/', ModeratorRegistrationView.as_view(), name='moderator-register'),
]
