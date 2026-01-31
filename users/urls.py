from django.urls import path
from .views import SignUpView, VerifyCode, NewVerifyCode, UserChangView, UserPhotoView, LoginView,\
    LogOutView, ForgotPasswordView, ResetPasswordView, ProfileView, ChangePasswordView


urlpatterns = [
    path('login/', LoginView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('forgot-pass/', ForgotPasswordView.as_view()),
    path('reset-pass/', ResetPasswordView.as_view()),
    path('signup/', SignUpView.as_view()),
    path('code-verify/', VerifyCode.as_view()),
    path('new-code-verify/', NewVerifyCode.as_view()),
    path('user-change-info/', UserChangView.as_view()),
    path('user-change-photo/', UserPhotoView.as_view()),
    path('profile/', ProfileView.as_view()),
    path('change-password/', ChangePasswordView.as_view()), 
]