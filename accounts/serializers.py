from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.encoding import force_bytes,smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import User
from .utils import Util




class UserRegtrationsSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_user(**validated_data)

class AdminRegtrationsSerializer(UserRegtrationsSerializer):
    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_superuser(**validated_data)

class ModeratorRegtrationsSerializer(UserRegtrationsSerializer):
    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_Moderator(**validated_data)

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password

class ChangeUserPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={"input_type": "password"}, write_only=True)
    password2 = serializers.CharField(max_length=255,style={"input_type": "password"}, write_only=True)
    class Meta:
        fields = ["password", "password2"]
        
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        user=self.context.get("user")
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist")

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        reset_url = f'http://localhost:8000/api/user/reset-password/{uid}/{token}/'
        
        Util.send_email({
            'email_subject': 'Password Reset email from django',
            'email_body': f'Click the link below to reset your password\n {reset_url}',
            'recipient_email': email
        })
        return attrs


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={"input_type": "password"}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={"input_type": "password"}, write_only=True)

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        uid = self.context.get("uid")
        token = self.context.get("token")

        # Check if passwords match
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")

        # Validate user ID and token
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user or UID")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is not valid or has expired")

        # Set the new password
        user.set_password(password)
        user.save()

        return attrs