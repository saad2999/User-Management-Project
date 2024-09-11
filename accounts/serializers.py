from rest_framework import serializers
from accounts.models import User

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
            raise serializers.ValidationError("Password must match")
        return attrs
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
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
            raise serializers.ValidationError("Password must match")
        user.set_password(password)
        user.save()
        return attrs
    
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ["email"]
        
def validate(self, attrs):
        user = User.objects.filter(self.email)
        if not user:
            raise serializers.ValidationError("User with this email does not exist")
        return attrs