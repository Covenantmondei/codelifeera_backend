from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

USER = "user"
DEVELOPER = "developer"
FOUNDER = "founder"

ROLE_CHOICES = [
    (USER, "User"),
    (DEVELOPER, "Developer"),
    (FOUNDER, "Founder"),
]


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        if not username:
            raise ValueError("The Username field must be set")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)
    
    
class Profile(AbstractUser):
    name = models.CharField(max_length=200, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True)
    bio = models.TextField(null=True, blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=USER)
    email_verified = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    def __str__(self):
        return f"{self.username} ({self.role})"
    
    def get_profile_picture(self):
        if self.avatar:
            return self.avatar.url


# @receiver(post_save, sender=settings.AUTH_USER_MODEL)
# def create_auth_token(sender, instance=None, created=False, **kwargs):
#     if created:
#         Token.objects.create(user=instance)


class UserType(models.Model):
    title = models.CharField(max_length=200, null=True )
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.title
    

class EmailVerification(models.Model):
    email = models.EmailField(unique=True)
    otp = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email


class ResetPassword(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    otp = models.IntegerField()
    timestamp = models.DateTimeField(default=timezone.now)


    def __str__(self) -> str:
        return self.profile.email
    

class ResetPasswordValuationToken(models.Model):
    reset_token = models.CharField(max_length=200)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.reset_token