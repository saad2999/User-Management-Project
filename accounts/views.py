from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserRegtrationsSerializer, UserLoginSerializer, UserProfileSerializer,ChangeUserPasswordSerializer
from django.contrib.auth import authenticate
from .customRenderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

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
