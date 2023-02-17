# from django.conf.urls import url
from django.urls import path, include
from .views import (
    UserApiView, UserLoginApiView, CodeSpinnetApiView
)
from .code_views import CodeSnippetView
# from django.conf.urls import handler403, handler404, handler500, include, url
from django.urls import re_path as url
urlpatterns = [
    # url(r'^code/(?P<id>\w+)$',
    #     CodeSpinnetApiView.as_view(), name='blogpost-list'),
    path('api', UserApiView.as_view()),
    path('login', UserLoginApiView.as_view()),
    path('code', CodeSpinnetApiView.as_view()),
    # path("your-site/", include(app_router.urls)),
    # path('<int:id>/', CodeSpinnetApiView.as_view())
    # url(r'^code/(?P<id>\d+)/$', CodeSnippetView.as_view(), name='shop-rud')
    url(r'^code/(?P<id>\d+)/$', CodeSnippetView.as_view(), name='shop-rud')
]
