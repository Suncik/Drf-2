from rest_framework import serializers
from rest_framework.exceptions import ValidationError, NotFound
from .models import User, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from baseapp.utility import email_or_phone, check_userinputtype
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.db.models import Q
#
# auth_validate
# create --
# validate_email_phone_number


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    auth_type = serializers.CharField(read_only=True, required=False)
    auth_status = serializers.CharField(read_only=True, required=False)
    
    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)


    class Meta:
        model = User
        fields = [
            'auth_type',
            'auth_status',
            'id'
        ]
        
    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.verify_code(VIA_EMAIL)
            #send_mail(user.email, code)
            print(code)
        elif user.auth_type == VIA_PHONE:
            code = user.verify_code(VIA_PHONE)
            #send_mail(user.email, code)
            print(code)
        else:
            data = {
            'success': 'False',
            'message': 'Telefon raqam yoki email togri kiriting'
            }
            raise ValidationError(data)
        user.save()
        return user
    
    def validate(self, data):
        data = self.auth_validate(data)
        return data
        
    @staticmethod
    def auth_validate(data):
        
        
        user_input = str(data.get('email_phone_number'))
        user_input_type = email_or_phone(user_input)
        print(user_input_type)
        
        if user_input_type == 'email':
            data = {
                'auth_type': VIA_EMAIL,
                'email': user_input
            }
        elif user_input_type == 'phone':
            data = {
                'auth_type': VIA_PHONE,
                'phone_number': user_input
            }            
        
        else:
            data = {
            'success': 'False',
            'message': 'Telefon raqam yoki email kiriting'
            }
        
            raise ValidationError(data)
        return data
    
    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            raise ValidationError('Bu email allaqachon mavjud')
        elif value and User.objects.filter(phone_number=value).exists():
            raise ValidationError('Bu telefon raqam allaqachon mavjud')
        return value
    
    def to_representation(self, instance):
        data =  super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data
    
        
class UserChangeInfoSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)    
    last_name = serializers.CharField(required=False)    
    username = serializers.CharField(required=False)    
    password = serializers.CharField(required=False)    
    confirm_password = serializers.CharField(required=False)
    
    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('password', None)
        if password and confirm_password and password != confirm_password:
            data = {
                'success': False,
                'message': 'Parollar mos emas'
            }
            raise ValidationError(data)
        
        if password:
            validate_password(password)
            validate_password(confirm_password)
        
        return data
    
    
    def validate_username(self, username):
        if username.isdigit() or len(username) < 5:
            data = {
                'success': False,
                'message': 'Username talabga mos kelamydi'
            }
            raise ValidationError(data)
        return username
    
    
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.password = validated_data.get('password')
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance


class UserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField()
    
    def update(self, instance, validated_data):
        photo = validated_data.get('photo', None)
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            print(photo)
            
        instance.save()
        return instance


class LoginSerializer(TokenObtainPairSerializer):
    
    def __init__(self, instance=None, data=..., **kwargs):
        super(LoginSerializer, self).__init__(instance, data, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)
        
    
    def auth_validate(self, data):
        userinput = data.get('userinput')
        password = data.get('password')

        usertype = check_userinputtype(userinput)
        if usertype == 'username':
            username=userinput
        elif usertype == 'email':
            user = User.objects.filter(email__iexact=userinput).first()
            self.get_user(user)
            username = user.username
        elif usertype == 'phone':
            user = User.objects.filter(phone_number=userinput).first()
            self.get_user(user)
            username = user.username
        else:
            data = {
                'success': False,
                'message': 'login xato'
            }
            
            raise ValidationError(data)
        
        authenticated_kwargs = {
            self.username_field: username,
            'password': password
        }
        
        user = authenticate(**authenticated_kwargs) #None
        if user and user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError({
                "success": False,
                'message': 'Siz hali login qilolmaysiz(toliq roxatdan otmagansiz)'
            })
            
        if not user:
            raise ValidationError({
                "success": False,
                "message": "Login yoki parol xato"
            })
        self.user = user
        return data

    def get_user(self, user):
        if not user:
            raise ValidationError({
                "success": False,
                "message": "Foydalanuvchi topilmadi"
            })
        return user

    
    
    def validate(self, attrs):
        data = self.auth_validate(attrs)
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        
        return data
    
    
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

        

class ForgotPasswordSerializer(serializers.Serializer):
    email_or_phone_ = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        
        email_or_phone_ = attrs.get('email_or_phone_', None)
        if email_or_phone_ is None:
            raise ValidationError(
                {
                    "success": False,
                    'message': "Email yoki telefon raqami kiritilishi shart!"
                }
            )
        user = User.objects.filter(Q(phone_number=email_or_phone_) | Q(email=email_or_phone_))
        if not user.exists():
            raise NotFound(detail="User not found")
        attrs['user'] = user.first()
        return attrs


class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password'
        )

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Parollaringiz qiymati bir-biriga teng emas"
                }
            )
        if password:
            validate_password(password)
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)
        
        
        
#profile api
#change pass api 

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "photo",
            "user_role",
            "auth_status",
            "auth_type",
        )
        read_only_fields = ("id", "user_role", "auth_status", "auth_type")


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data["new_password"] != data["confirm_new_password"]:
            raise ValidationError({
                "success": False,
                "message": "Yangi parollar mos emas"
            })
        validate_password(data["new_password"])
        return data

            
        
            
        
        
        
    
        
        
            

    
    
    
        
        
    
        
    