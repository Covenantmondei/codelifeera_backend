from django.urls import path,include
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

app_name = 'accounts'

urlpatterns = [
    path('register/', views.RegisterUser.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('verify-email/', views.VerifyEmail.as_view(), name='verify-email'),
    path('resend-otp/', views.ResendOtpCode.as_view(), name='resend-otp'),
    path('reset/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('verify-reset-otp/', views.VerifyResetOtp.as_view(), name='verify-reset-otp'),
    path('edit-profile/', views.EditProfile.as_view(), name='edit-profile'),
]