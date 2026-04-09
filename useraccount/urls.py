from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from .views import (
    register_view,
    login_view,
    verify_email_view,
    resend_email_verification_view,
    email_confirm_redirect,
    password_reset_view,
    password_reset_confirm_redirect,
    password_reset_confirm_view,
    change_password_view,
    profile_view,
    logout_view,
)

urlpatterns = [
    path("register/", register_view, name="register"),
    path("login/", login_view, name="login"),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("verify-token/", TokenVerifyView.as_view(), name="token_verify"),
    path("register/verify-email/", verify_email_view, name="rest_verify_email"),
    path(
        "register/resend-email/",
        resend_email_verification_view,
        name="rest_resend_email",
    ),
    path(
        "account-confirm-email/<str:uidb64>/<str:token>/",
        email_confirm_redirect,
        name="account_confirm_email",
    ),
    path(
        "account-confirm-email/",
        verify_email_view,
        name="account_email_verification_sent",
    ),
    path("password/reset/", password_reset_view, name="rest_password_reset"),
    path(
        "password/reset/confirm/<str:uidb64>/<str:token>/",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    path(
        "password/reset/confirm/",
        password_reset_confirm_view,
        name="password_reset_confirm_api",
    ),
    path("change-password/", change_password_view, name="change_password"),
    path("profile/", profile_view, name="profile"),
    path("logout/", logout_view, name="logout"),
]
