from django.db import models
from django.contrib.auth.models import User


class User(models.Model):
    first_name = models.CharField(max_length=50)
    # last_name = models.DateTimeField(auto_now_add = True, auto_now = False, blank = True)
    last_name = models.CharField(max_length=100)
    # email = models.BooleanField(default = False, blank = True)
    email = models.EmailField(max_length=100)
    # password = models.DateTimeField(auto_now = True, blank = True)
    password = models.CharField(max_length=200)
    # user = models.ForeignKey(User, on_delete = models.CASCADE, blank = True, null = True)

    def __str__(self):
        return self.first_name + self.last_name


class UserLoginTokens(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    access_token = models.CharField('Access Token', max_length=400)
    refresh_token = models.CharField('Refresh Token', max_length=400)


class CodeSnippet(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    code = models.CharField(max_length=10000)
    title = models.CharField(max_length=80, default=None)
    language = models.CharField(max_length=20, default=None)
    public = models.BooleanField(default=None)
