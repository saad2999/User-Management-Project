from rest_framework import serializers
from accounts.models import User
from django.utils.encoding import smart_str, force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts.utils import Util





class UserRegtrationsSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}
        
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")
        return attrs
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class AdminRegtrationsSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}
        
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")
        return attrs
    def create(self, validated_data):
        user = User.objects.create_superuser(**validated_data)
        return user
    
class ModeratorRegtrationsSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}
        
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")
        return attrs
    def create(self, validated_data):
        user = User.objects.create_Moderator(**validated_data)
        return user
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email", "password"]

class UserProfileSerializer(serializers.ModelSerializer):    
    class Meta:
        model = User
        fields = ["id", "email", "name"]
        
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
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ["email"]
        
    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.pk))
            token=PasswordResetTokenGenerator().make_token(user)
            link= link = f'http://localhost:8000/api/user/reset-password/{uid}/{token}/'
            data={
                'email_subject':'Password Reset email from django',
                'email_body': f'Click the link below to reset your password\n {link}',
                'recipient_email':email
                }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("User with this email does not exist")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={"input_type": "password"}, write_only=True)
    password2 = serializers.CharField(max_length=255,style={"input_type": "password"}, write_only=True)
   
    class Meta:
        fields = ["password", "password2"]
        
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.pop("password2")
        uid=self.context.get("uid")
        token=self.context.get("token")
        
        if password != password2:
            raise serializers.ValidationError("Password and confirm password must match")
        id=smart_str(urlsafe_base64_decode(uid))
        user=User.objects.get(pk=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is not valid or expired")
        user.set_password(password)
        user.save()
        return attrs