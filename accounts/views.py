from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import *
from django.contrib.auth import authenticate
from .customRenderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from accounts.models import User
from accounts.custompremisson import IsAdminUser, IsModeratorOrReadOnly

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer = UserRegtrationsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({"token":token,"msg":"User Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserUpdateView(APIView):
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated,IsAdminUser,IsModeratorOrReadOnly]

    def put(self, request, pk=None):
        user = User.objects.get(pk=pk)
        serializer = UserProfileSerializer(user, data=request.data, partial=False)  # `partial=False` for full update
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User profile updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def patch(self, request,pk=None):
        user = User.objects.get(pk=pk)
        serializer = UserProfileSerializer(user, data=request.data, partial=True)  # `partial=True` for partial update
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User profile partially updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserDeleteView(APIView):
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated,IsAdminUser,IsModeratorOrReadOnly]

    def delete(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk) 
            
                      
            user.delete()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    
class AdminRegistrationView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer = AdminRegtrationsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({"token":token,"msg":"User Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ModeratorRegistrationView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer = ModeratorRegtrationsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({"token":token,"msg":"User Registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLoginView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer= UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            user = authenticate(email=email, password=password)
            
            if user:
                token=get_tokens_for_user(user)
                return Response({"token":token,"message": "Login successful"}, status=status.HTTP_200_OK)
            else:
                return Response({"errors": {"non_field_errors":['email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class UserProflieView(APIView):
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated]
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeUserPasswordView(APIView):
    renderer_classes = (UserRenderer,)
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer=ChangeUserPasswordSerializer(data=request.data,context={"user":request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"message":"Password changed successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class SendPasswordResetEmailView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"msg":"Password reset email has been sent"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserPasswordResetView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request, uidb64, token):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uidb64, 'token': token})
        if serializer.is_valid():
          
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)