from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'first_name', 'last_name', 'password', 'is_active', 'is_blocked','date_joined' )

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    verification_code = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

class SendVerificationCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ChangePasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ChangePasswordSerializer(serializers.Serializer):
    verification_code = serializers.CharField(max_length=6)
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)