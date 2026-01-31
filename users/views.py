from django.shortcuts import render
from rest_framework.generics import CreateAPIView, UpdateAPIView
from .models import User, NEW, CODE_VERIFIED, VIA_EMAIL, VIA_PHONE, DONE, PHOTO_DONE
from rest_framework.views import APIView
from .serializers import SignUpSerializer, UserChangeInfoSerializer, UserPhotoSerializer,\
    LoginSerializer, LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from rest_framework import permissions
from datetime import datetime
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.core.exceptions import ObjectDoesNotExist
from baseapp.utility import email_or_phone
from .serializers import SignUpSerializer, UserChangeInfoSerializer, UserPhotoSerializer,\
    LoginSerializer, LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, \
    ProfileSerializer, ChangePasswordSerializer


class SignUpView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (permissions.AllowAny, )
    
    
class VerifyCode(APIView):
    permission_classes = (permissions.IsAuthenticated, )
    
    def post(self, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')
        
        self.check_verify_code(user, code)
        data = {
            'success': True,
            'auth_status': user.auth_status,
            'access_token': user.token()['access'],
            'refresh': user.token()['refresh_token']
        }
        return Response(data)
        
    @staticmethod
    def check_verify_code(user, code):    #12:23    12:26   12: 27
        verify = user.verify_codes.filter(code=code, confirmed=False, expiration_time__gte=datetime.now())
        if not verify.exists():
            data = {
                'success': False,
                'message': 'Kod eskirgan yoki xato'
            }
            raise ValidationError(data)
        else:
            verify.update(confirmed=True)

        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
            
        return True
            
            
class NewVerifyCode(APIView):
    permission_classes = (permissions.IsAuthenticated, )
    
    def get(self, request):
        user = request.user
        self.check_code(user)
        if user.auth_type == VIA_EMAIL:
            code = user.verify_code(VIA_EMAIL)
            #send_mail(user.email, code)
            print(code)
        elif user.auth_type == VIA_PHONE:
            code = user.verify_code(VIA_PHONE)
            #send_mail(user.email, code)
            print(code)
        
        data = {
            'success': True,
            'message': 'Code yuborildi'
        }
        return Response(data)

        
    @staticmethod
    def check_code(user):
        verify = user.verify_codes.filter(confirmed=False, expiration_time__gte=datetime.now())
        if verify.exists() :
            data = {
                'success': False,
                'message': 'Sizda active code mavjud'
            }
            raise ValidationError(data)
        if user.auth_status != NEW:
            data = {
                'success': False,
                'message': 'Sizda code tasdiqlangan'
            }
            raise ValidationError(data)
        
        return True
    

class UserChangView(UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated, )
    queryset = User.objects.all()
    serializer_class = UserChangeInfoSerializer
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        super().update(request, *args, **kwargs)
        data = {
                'success': True,
                'message': 'Malumotlaringiz yangilandi'
            }
        return Response(data)
    
    def partial_update(self, request, *args, **kwargs):
        super().update(request, *args, **kwargs)
        data = {
                'success': True,
                'message': 'Malumotlaringiz qisman yangilandi'
            }
        return Response(data)
        

class UserPhotoView(APIView):
    permission_classes = (permissions.IsAuthenticated, )
    
    def put(self, request):
        serializer = UserPhotoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.request.user
        serializer.update(user, validated_data=serializer.validated_data)
        data = {
            'success': True, 
            'message': 'Sizning rasmingiz ozgartirildi'
        }
        return Response(data)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer        
    
    
class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': "You are loggout out"
            }
            return Response(data, status=205)
        except TokenError:
            return Response({"message": 'Xatolik', "status": 400}, status=400) 
        except Exception as e:
            return Response({"message": 'Xatolik'})   
    

class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny,]

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone_ = serializer.validated_data.get('email_or_phone_')
        user = serializer.validated_data.get('user')
        if email_or_phone(email_or_phone_) == 'phone':
            code = user.verify_code(VIA_PHONE)
            # send_email(email_or_phone, code)
            print(code)
        elif email_or_phone(email_or_phone_) == 'email':
            code = user.verify_code(VIA_EMAIL)
            # send_email(email_or_phone, code)
            print(code)

        return Response(
            {
                "success": True,
                'message': "Tasdiqlash kodi muvaffaqiyatli yuborildi",
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token'],
                "user_status": user.auth_status,
            }, status=200
        )


class ResetPasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.IsAuthenticated, ]
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist as e:
            raise NotFound(detail='User not found')
        return Response(
            {
                'success': True,
                'message': "Parolingiz muvaffaqiyatli o'zgartirildi",
                'access': user.token()['access'],
                'refresh': user.token()['refresh_token'],
            }
        )
class ProfileView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request):
        serializer = ProfileSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = ProfileSerializer(
            request.user,
            data=request.data,
            partial=False
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "success": True,
            "message": "Profil yangilandi",
            "data": serializer.data
        })

    def patch(self, request):
        serializer = ProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "success": True,
            "message": "Profil qisman yangilandi",
            "data": serializer.data
        })


class ChangePasswordView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.check_password(serializer.validated_data["old_password"]):
            raise ValidationError({
                "success": False,
                "message": "Eski parol noto'g'ri"
            })

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({  
            "success": True,
            "message": "Parol muvaffaqiyatli o'zgartirildi",
            "access": user.token()["access"],
            "refresh": user.token()["refresh_token"]
        })