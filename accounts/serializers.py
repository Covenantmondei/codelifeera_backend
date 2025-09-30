from rest_framework import serializers
from .models import Profile, UserType
from django.utils.crypto import get_random_string
from django.core.exceptions import ValidationError


class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    role = serializers.ChoiceField(choices=[('user', 'User'), ('developer', 'Developer'), ('founder', 'Founder')], default='user')
    password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if Profile.objects.filter(email=value).exists():
            raise ValidationError("Email is already in use.")
        return value
    

    def validate_username(self, value):
        if Profile.objects.filter(username=value).exists():
            raise ValidationError("Username is already in use.")
        return value


    def create(self, validated_data):
        user = Profile.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data.get('role', 'user')
        )
        return user
    

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'username', 'email', 'role', 'email_verified', 'created_on']
        read_only_fields = ['id', 'email_verified', 'created_on']


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class EditPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
    # username = serializers.CharField() 
    email = serializers.EmailField()


class UserTypeSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserType
        fields = '__all__'


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        username = data.get('username')

        try:
            owner = Profile.objects.get(email=email, username=username)
        except Profile.DoesNotExist:
            raise ValidationError("No user found with the provided email and username.")
        return data

    def save(self):
        user = Profile.objects.get(email=self.validated_data['email'])
        otp = get_random_string(6,'0123456789')
        return user, otp
    

class EditProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['name', 'email', 'bio', 'avatar']