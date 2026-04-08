from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpResponse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer,
    ResendEmailVerificationSerializer,
    VerifyEmailSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    UserSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
)
from .tokens import email_verification_token

User = get_user_model()


# =========================
# REGISTER
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    # Make sure user is inactive until verified
    user.is_active = False
    user.save()

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_verification_token.make_token(user)

    verification_link = request.build_absolute_uri(
        f"/useraccount/account-confirm-email/{uid}/{token}/"
    )

    send_mail(
        subject="Verify your email",
        message=f"Click the link to verify your email:\n{verification_link}",
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )

    return Response(
        {
            "message": "User registered successfully. Check your email to verify your account.",
            "user": UserSerializer(user).data,
        },
        status=status.HTTP_201_CREATED,
    )


# =========================
# LOGIN
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    username = serializer.validated_data["username"]
    password = serializer.validated_data["password"]

    user = authenticate(username=username, password=password)

    if user is None:
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        return Response(
            {"error": "Please verify your email before logging in."},
            status=status.HTTP_403_FORBIDDEN,
        )

    refresh = RefreshToken.for_user(user)

    return Response(
        {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": UserSerializer(user).data,
        },
        status=status.HTTP_200_OK,
    )


# =========================
# VERIFY EMAIL (API)
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email_view(request):
    serializer = VerifyEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    uidb64 = serializer.validated_data["uidb64"]
    token = serializer.validated_data["token"]

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response(
            {"error": "Invalid user"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if user.is_active:
        return Response(
            {"message": "Account already verified"},
            status=status.HTTP_200_OK,
        )

    if email_verification_token.check_token(user, token):
        user.is_active = True
        user.save()
        return Response(
            {"message": "Successfully activated"},
            status=status.HTTP_200_OK,
        )

    return Response(
        {"error": "Invalid or expired token"},
        status=status.HTTP_400_BAD_REQUEST,
    )


# =========================
# VERIFY EMAIL (BROWSER LINK)
# =========================
@api_view(["GET"])
@permission_classes([AllowAny])
def email_confirm_redirect(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return HttpResponse("Invalid verification link.", status=400)

    if user.is_active:
        return HttpResponse("Email already verified.", status=200)

    if email_verification_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse(
            "Email verified successfully. You can now log in.",
            status=200,
        )

    return HttpResponse("Verification link is invalid or expired.", status=400)


# =========================
# RESEND VERIFICATION EMAIL
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def resend_email_verification_view(request):
    serializer = ResendEmailVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"error": "User not found"},
            status=status.HTTP_404_NOT_FOUND,
        )

    if user.is_active:
        return Response(
            {"message": "Email is already verified"},
            status=status.HTTP_200_OK,
        )

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_verification_token.make_token(user)

    verification_link = request.build_absolute_uri(
        f"/useraccount/account-confirm-email/{uid}/{token}/"
    )

    send_mail(
        subject="Resend Email Verification",
        message=f"Click the link to verify your email:\n{verification_link}",
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )

    return Response(
        {"message": "Verification email resent successfully"},
        status=status.HTTP_200_OK,
    )


# =========================
# PASSWORD RESET REQUEST
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_view(request):
    serializer = PasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"error": "User not found"},
            status=status.HTTP_404_NOT_FOUND,
        )

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    reset_link = request.build_absolute_uri(
        f"/useraccount/password/reset/confirm/{uid}/{token}/"
    )

    send_mail(
        subject="Password Reset",
        message=f"Click the link to reset your password:\n{reset_link}",
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )

    return Response(
        {"message": "Password reset email sent"},
        status=status.HTTP_200_OK,
    )


# =========================
# PASSWORD RESET CONFIRM (OPTIONAL BROWSER MESSAGE)
# =========================
@api_view(["GET"])
@permission_classes([AllowAny])
def password_reset_confirm_redirect(request, uidb64, token):
    return HttpResponse(
        f"Use this UID and token in your API request to reset password.\n\nuidb64={uidb64}\ntoken={token}",
        status=200,
        content_type="text/plain",
    )


# =========================
# PASSWORD RESET CONFIRM (API)
# =========================
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm_view(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data["user"]
    new_password = serializer.validated_data["new_password"]

    user.set_password(new_password)
    user.save()

    return Response(
        {"message": "Password reset successful"},
        status=status.HTTP_200_OK,
    )


# =========================
# change password
# =========================


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    serializer = ChangePasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = request.user
    old_password = serializer.validated_data["old_password"]
    new_password = serializer.validated_data["new_password"]

    # Check old password
    if not user.check_password(old_password):
        return Response(
            {"error": "Old password is incorrect"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Prevent reusing same password
    if old_password == new_password:
        return Response(
            {"error": "New password cannot be the same as old password"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user.set_password(new_password)
    user.save()

    return Response(
        {"message": "Password changed successfully"},
        status=status.HTTP_200_OK,
    )


# =========================
# PROFILE
# =========================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def profile_view(request):
    return Response(UserSerializer(request.user).data)
