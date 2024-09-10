
from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserProflieView,ChangeUserPasswordView

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/", UserProflieView.as_view(), name="profile"),
    path("changepassword/", ChangeUserPasswordView.as_view(), name="changepassword"),
]
