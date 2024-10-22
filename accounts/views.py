from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import *
from .models import User
from .customRenderer import UserRenderer
from .custompremisson import IsAdminUser, IsModeratorOrReadOnly
from .throttle import PasswordThrottle
from rest_framework.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserRegtrationsSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({"token": token, "msg": "User Registration successful"}, status=status.HTTP_201_CREATED)

class UserUpdateView(generics.UpdateAPIView):
    queryset = User.objects.all()
    renderer_classes = (UserRenderer,)
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser, IsModeratorOrReadOnly]

class UserDeleteView(generics.DestroyAPIView):
    queryset = User.objects.all()
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated, IsAdminUser, IsModeratorOrReadOnly]

class AdminRegistrationView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = AdminRegtrationsSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({"token": token, "msg": "Admin Registration successful"}, status=status.HTTP_201_CREATED)

class ModeratorRegistrationView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = ModeratorRegtrationsSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({"token": token, "msg": "Moderator Registration successful"}, status=status.HTTP_201_CREATED)

class UserLoginView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserLoginSerializer
    throttle_classes = [PasswordThrottle]

    def create(self, request, *args, **kwargs):
        logger.info("UserLoginView.post method called")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")
        user = authenticate(email=email, password=password)
        if user:
            token = get_tokens_for_user(user)
            return Response({"token": token, "message": "Login successful"}, status=status.HTTP_200_OK)
        raise ValidationError({"non_field_errors": ['Email or password is not valid']})

class UserProfileView(generics.RetrieveAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

class ChangeUserPasswordView(generics.GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = ChangeUserPasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={"user": request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = SendPasswordResetEmailSerializer
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            return Response({"msg": "Password reset email has been sent"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    

class UserPasswordResetView(generics.CreateAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserPasswordResetSerializer

    def post(self, request, uidb64, token):
        # Pass the UID and token to the serializer via the context
        serializer = self.get_serializer(data=request.data, context={'uid': uidb64, 'token': token})
        
        if serializer.is_valid():
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
from django.shortcuts import redirect

def redirect_to_docs(request):
    return redirect('/docs/')
