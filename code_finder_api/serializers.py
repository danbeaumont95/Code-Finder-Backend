from rest_framework import serializers
from .models import User, CodeSnippet


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password"]


class CodeSpinnerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CodeSnippet
        fields = ["user", "code", "title", "language", "public"]
