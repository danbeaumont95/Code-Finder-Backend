
from rest_framework import generics
from .models import User, UserLoginTokens, CodeSnippet

from .serializers import CodeSpinnerSerializer
from .views import return_response
from rest_framework import status

# Get code snippet by id


class CodeSnippetView(generics.RetrieveUpdateDestroyAPIView):
    lookup_field = 'id'
    serializer_class = CodeSpinnerSerializer

    def get_queryset(self):
        print('here1')
        return CodeSnippet.objects.all()
