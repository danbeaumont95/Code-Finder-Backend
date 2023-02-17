# todo/todo_api/views.py
import time
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from .models import User, UserLoginTokens, CodeSnippet
from .serializers import UserSerializer, CodeSpinnerSerializer
from django.contrib.auth.hashers import make_password, check_password
import environ
import os
from django.core.exceptions import ImproperlyConfigured
from rest_framework.decorators import api_view, permission_classes
from django.forms.models import model_to_dict

env = environ.Env()
environ.Env.read_env()


def return_response(data, message, status):
    return Response({'data': data, 'message': message, 'status': status})


def get_env_variable(var_name):
    try:
        return os.environ[var_name]
    except KeyError:
        error_msg = "set the %s environment variable" % var_name
        raise ImproperlyConfigured(error_msg)


class UserApiView(APIView):
    # add permission to check if user is authenticated
    # permission_classes = [permissions.IsAuthenticated]

    # 1. List all
    def get(self, request, *args, **kwargs):
        '''
        List all the todo items for given requested user
        '''
        # users = User.objects.filter(id=request.user.id)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 2. Create
    def post(self, request, *args, **kwargs):
        '''
        Create the Todo with given todo data
        '''
        data = {
            'first_name': request.data.get('first_name'),
            'last_name': request.data.get('last_name'),
            'email': request.data.get('email'),
            'password': request.data.get('password'),
            # 'user': request.user.id
        }

        hashed_password = make_password(data['password'])
        email_already_exists = User.objects.filter(
            email=data['email']).exists()
        if email_already_exists == True:
            return return_response([],  {'email': 'Email already exists'}, status.HTTP_400_BAD_REQUEST)
        data['password'] = hashed_password
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            # return Response({'data': serializer.data, 'message': 'Success'}, status=status.HTTP_201_CREATED)
            return return_response(serializer.data, 'Success', status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserDetailApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]

#     def get_object(self, todo_id, user_id):
#         '''
#         Helper method to get the object with given todo_id, and user_id
#         '''
#         try:
#             return User.objects.get(id=todo_id, user = user_id)
#         except User.DoesNotExist:
#             return None

#     # 3. Retrieve
#     def get(self, request, todo_id, *args, **kwargs):
#         '''
#         Retrieves the Todo with given todo_id
#         '''
#         user_instance = self.get_object(todo_id, request.user.id)
#         if not todo_instance:
#             return Response(
#                 {"res": "Object with todo id does not exists"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         serializer = TodoSerializer(todo_instance)
#         return Response(serializer.data, status=status.HTTP_200_OK)

#     # 4. Update
#     def put(self, request, todo_id, *args, **kwargs):
#         '''
#         Updates the todo item with given todo_id if exists
#         '''
#         todo_instance = self.get_object(todo_id, request.user.id)
#         if not todo_instance:
#             return Response(
#                 {"res": "Object with todo id does not exists"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
#         data = {
#             'task': request.data.get('task'),
#             'completed': request.data.get('completed'),
#             'user': request.user.id
#         }
#         serializer = TodoSerializer(instance = todo_instance, data=data, partial = True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     # 5. Delete
#     def delete(self, request, todo_id, *args, **kwargs):
#         '''
#         Deletes the todo item with given todo_id if exists
#         '''
#         todo_instance = self.get_object(todo_id, request.user.id)
#         if not todo_instance:
#             return Response(
#                 {"res": "Object with todo id does not exists"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
#         todo_instance.delete()
#         return Response(
#             {"res": "Object deleted!"},
#             status=status.HTTP_200_OK
#         )


def token_response(access_token: str, refresh_token: str):
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


def signJWT(user_id: str):
    jwt_algorithm = env('algorithm')
    jwt_secret = env('secret')
    access_payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    refresh_payload = {
        "user_id": user_id,
        "expires": time.time() + 30000000
    }
    access_token = jwt.encode(
        access_payload, jwt_secret, algorithm=jwt_algorithm)
    refresh_token = jwt.encode(
        refresh_payload, jwt_secret, algorithm=jwt_algorithm)
    return token_response(access_token, refresh_token)


class UserLoginApiView(APIView):
    def post(self, request, *args, **kwargs):

        data = {
            'email': request.data.get('email'),
            'password': request.data.get('password'),
            # 'user': request.user.id
        }
        user = User.objects.filter(email=request.data['email'])

        if len(user) < 1:
            # return Response({'Error': 'No user found with those details'})
            return Response({'data': [], 'message': {'Error': 'No user found with those details'}, 'status': status.HTTP_400_BAD_REQUEST})

        # check = check_password(request.data['password'], data['password'])

        hashed_password = user[0].password
        user_id = user[0].id

        check = check_password(request.data['password'], hashed_password)

        if check == False:
            # return Response({'Error': 'No user found with those details'})
            return Response({'data': [], 'message': {'Error': 'No user found with those details'}, 'status': status.HTTP_400_BAD_REQUEST})

        token = signJWT(user_id)

        access_token = token['access_token']
        refresh_token = token['refresh_token']

        saved_token = UserLoginTokens.objects.create(
            access_token=access_token, refresh_token=refresh_token, user_id=user_id
        )
        saved_token.save()
        return Response({
            'message': 'Success',
            'access': access_token,
            'refresh': refresh_token,
            'id': user_id
        })


class CodeSpinnetApiView(APIView):
    lookup_field = 'id'

    @api_view(['POST', 'GET'])
    def get_queryset(self):
        # return super().get_queryset()
        queryset = CodeSnippet.objects.filter(pk=self.kwargs['id'])

    def get(self, request):
        bearer_token = request.headers.get('authorization')

        if bearer_token is None:
            return return_response([], {'Error': 'Bearer Token required'}, status.HTTP_400_BAD_REQUEST)
        slice = bearer_token[7:]

        user_token_amount = UserLoginTokens.objects.filter(
            access_token=slice).count()

        if user_token_amount == 0 or user_token_amount < 1:
            return return_response([], {'Error': 'No user found'}, status.HTTP_400_BAD_REQUEST)

        user_token_id = UserLoginTokens.objects.filter(
            access_token=slice).values('user_id')

        user_id = user_token_id[0]['user_id']

        user = User.objects.get(id=user_id)

        public_code_snippets = CodeSnippet.objects.filter(
            public=True).values()

        public_code_snippets_not_by_me = []
        for item in public_code_snippets:
            if item['user_id'] != user_id:
                public_code_snippets_not_by_me.append(item)

        all_code_snippets_by_me = CodeSnippet.objects.filter(
            user=user).values()

        code_snippets_by_me = []
        for item in all_code_snippets_by_me:
            code_snippets_by_me.append(item)

        result = []
        public_code_snippets_not_by_me.extend(code_snippets_by_me)
        for myDict in public_code_snippets_not_by_me:
            if myDict not in result:
                result.append(myDict)

        return return_response(result, 'Success', status.HTTP_200_OK)

    def post(self, request):
        bearer_token = request.headers.get('authorization')

        if bearer_token is None:
            return return_response([], {'Error': 'Bearer Token required'}, status.HTTP_400_BAD_REQUEST)
        slice = bearer_token[7:]

        user_token_amount = UserLoginTokens.objects.filter(
            access_token=slice).count()

        if user_token_amount == 0 or user_token_amount < 1:
            return return_response([], {'Error': 'No user found'}, status.HTTP_400_BAD_REQUEST)

        user_token_id = UserLoginTokens.objects.filter(
            access_token=slice).values('user_id')

        user_id = user_token_id[0]['user_id']

        user = User.objects.get(id=user_id)

        data = {
            'code': request.data.get('code'),
            'title': request.data.get('title'),
            'language': request.data.get('language'),
            'public': request.data.get('public'),
        }

        CodeSnippet.objects.create(
            user=user, code=data['code'], title=data['title'], language=data['language'], public=data['public'])

        return return_response([], 'Success', status.HTTP_201_CREATED)

    def put(self, request):
        bearer_token = request.headers.get('authorization')

        if bearer_token is None:
            return return_response([], {'Error': 'Bearer Token required'}, status.HTTP_400_BAD_REQUEST)
        slice = bearer_token[7:]

        user_token_amount = UserLoginTokens.objects.filter(
            access_token=slice).count()

        if user_token_amount == 0 or user_token_amount < 1:
            return return_response([], {'Error': 'No user found'}, status.HTTP_400_BAD_REQUEST)

        user_token_id = UserLoginTokens.objects.filter(
            access_token=slice).values('user_id')

        user_id = user_token_id[0]['user_id']

        code_snippets = request.data.get('codeSnippet')

        if user_id != code_snippets['user_id']:
            return return_response([], {'Error': 'Cannot update code snippet not created by you'}, status.HTTP_400_BAD_REQUEST)

        updated_code_snippet = CodeSnippet.objects.filter(
            id=code_snippets['id']).update(code=code_snippets['code'], title=code_snippets['title'], language=code_snippets['language'], public=code_snippets['public'])

        if updated_code_snippet == 1:
            return return_response([], 'Success', status.HTTP_201_CREATED)
