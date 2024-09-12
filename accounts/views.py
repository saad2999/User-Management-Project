from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.generics import GenericAPIView
from .serializers import *
from django.contrib.auth import authenticate
from .customRenderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from accounts.models import User
from accounts.custompremisson import IsAdminUser, IsModeratorOrReadOnly
from accounts.throttle import PasswordThrottle
from rest_framework.exceptions import Throttled, ValidationError
import logging
logger = logging.getLogger(__name__)




def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserRegtrationsSerializer
    

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token": token, "msg": "User Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser, IsModeratorOrReadOnly]

    def put(self, request, pk=None):
        user = User.objects.get(pk=pk)
        serializer = self.get_serializer(user, data=request.data, partial=False)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User profile updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk=None):
        user = User.objects.get(pk=pk)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User profile partially updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.generics import GenericAPIView

class UserDeleteView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated, IsAdminUser, IsModeratorOrReadOnly]

    def get_serializer(self, *args, **kwargs):
        return None  # No need for a serializer for delete

    def delete(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class AdminRegistrationView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = AdminRegtrationsSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token": token, "msg": "Admin Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ModeratorRegistrationView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = ModeratorRegtrationsSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token": token, "msg": "Moderator Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserLoginSerializer
    throttle_classes = [PasswordThrottle]

    def post(self, request):
        logger.info("UserLoginView.post method called")
        try:
            logger.info("Checking throttles")
            self.check_throttles(request)
            logger.info("Throttle check passed")
            
            logger.info("Validating serializer")
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            logger.info(f"Attempting to authenticate user: {email}")
            user = authenticate(email=email, password=password)
            
            if user:
                token = get_tokens_for_user(user)
                logger.info(f"User {email} authenticated successfully")
                return Response({"token": token, "message": "Login successful"}, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Authentication failed for user: {email}")
                raise ValidationError({"non_field_errors": ['Email or password is not valid']})

        except Throttled as e:
            logger.error(f"Request throttled: {str(e.detail)}")
            return Response({"errors": {"message": str(e.detail)}}, status=e.status_code)
        
        except ValidationError as e:
            logger.error(f"Validation error: {str(e.detail)}")
            return Response({"errors": e.detail}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Unexpected error in UserLoginView: {str(e)}")
            return Response({"errors": {"message": str(e)}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserProflieView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeUserPasswordView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = ChangeUserPasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={"user": request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = SendPasswordResetEmailSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            return Response({"msg": "Password reset email has been sent"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    serializer_class = UserPasswordResetSerializer

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data, context={'uid': uidb64, 'token': token})
        if serializer.is_valid():
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
