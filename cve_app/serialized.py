from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.models import User
from .models import CVEdetails, SingleCve


class SignupSerializer(serializers.Serializer):
    name = serializers.CharField()
    gmail = serializers.CharField()
    password = serializers.CharField()
    conf_pass = serializers.CharField()

    def validate(self, data):
        for i in data.items():
            if i[1] == "":
                raise ValidationError('All the fields must be filled')
        validators = '/^&*$#@!?,'
        if len(data['name']) < 3:
            raise ValidationError(
                'username field must contain greater then 2 characters')
        if len(data['gmail']) < 4 or '@' not in data['gmail']:
            raise ValidationError("your email must be valid")
        if len(User.objects.filter(email=data['gmail'])) > 0:
            raise ValidationError("User with this email already exists")
        if len(data['password']) < 8:
            raise ValidationError(
                "password and confirm password fields must greater than 7 characters")
        if len(data['conf_pass']) < 8:
            raise ValidationError(
                "password and confirm password fields must greater than 7 characters")
        if data['password'] != data['conf_pass']:
            raise ValidationError("Both the password fileds must be same")
        val_c = 0
        for i in validators:
            for j in data['password']:
                if i == j:
                    val_c += 1
        if val_c < 2:
            raise ValidationError(
                f"password must contain atleast 2 characters from these {validators} ")
        return data


class LoginSerializer(serializers.Serializer):
    gmail = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        for i in data.items():
            if i[1] == "":
                raise ValidationError("All the fields must be filled")
        if len(data['gmail']) < 4 or '@' not in data['gmail']:
            raise ValidationError("your email must be valid")
        if len(data['password']) < 8:
            raise ValidationError(
                "password must greater than 7 characters")
        return data


class CveSerializer(serializers.ModelSerializer):
    class Meta:
        model = CVEdetails
        fields = '__all__'


class SingleSerializer(serializers.ModelSerializer):
    class Meta:
        model = SingleCve
        fields = '__all__'
