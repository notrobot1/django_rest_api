from django.contrib.auth.hashers import make_password
from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from .models import *
#from django.contrib.auth.models import User
from django.contrib.auth import get_user_model


class UserReg(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ( 'username', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user




# class UserReg(serializers.ModelSerializer):
#     User = get_user_model()
#     class Meta:
#         model = User
#         fields = ('email', 'username', 'password')
#         extra_kwargs = {'password': {'write_only': True}}
#
#     def create(self, validated_data):
#         user = User(
#             email=validated_data['email'],
#             username=validated_data['username'],
#         )
#         user.set_password(validated_data['password'])
#         user.save()
#         return user



class UserSerializer1(serializers.ModelSerializer):
    User = get_user_model()
    class Meta:
        model = User
        fields = ['id','username', 'email', 'first_name', 'last_name']




class ExecutorSerializer(serializers.ModelSerializer):
    User = get_user_model()
    class Meta:
        model = User
        fields = ['id','username', 'email', 'first_name', 'last_name', 'date_joined', 'birth_date', 'city', 'country', 'family_status', 'gender']




class CreateExecutorSerializer(serializers.ModelSerializer):
    User = get_user_model()
    # old_password = serializers.CharField(required=True)
    # new_password = serializers.CharField(required=True)
    #password = serializers.CharField(required=True)

    #print(password)
    class Meta:
        model = User
        fields = '__all__'




class ChangePasswordSerializer(serializers.Serializer):

    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password1 = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password2 = serializers.CharField(max_length=128, write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _('Your old password was entered incorrectly. Please enter it again.')
            )
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': _("The two password fields didn't match.")})
        password_validation.validate_password(data['new_password1'], self.context['request'].user)
        return data

    def save(self, **kwargs):

        password = self.validated_data['new_password1']
        user = self.context['request'].user
        user.set_password(password)


        user.save()
        return user



class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email' ,'city', 'country', 'family_status','gender','birth_date')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'city': {'required': True},
            'country': {'required': True},
            'family_status': {'required': True},
            'gender': {'required': True},
            'birth_date': {'required': True}
        }

    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        return value

    def validate_username(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "This username is already in use."})
        return value

    def update(self, instance, validated_data):
        instance.first_name = validated_data['first_name']
        instance.last_name = validated_data['last_name']
        instance.email = validated_data['email']
        instance.username = validated_data['username']
        instance.city = validated_data['city']
        instance.country = validated_data['country']
        instance.family_status = validated_data['family_status']
        instance.gender = validated_data['gender']
        instance.birth_date = validated_data['birth_date']
        instance.save()

        return instance




