"""backend_developer_intern URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from rest_framework.authtoken.views import ObtainAuthToken 
from Authentication.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path("jwt/token/",TokenObtainPairView.as_view()),
    path("jwt/token/refresh/",TokenRefreshView.as_view()),
    path('user-role/create/',UserRoleCreateView.as_view()),
    path('user-role/list/',UserRoleListView.as_view()),
     path('user-role/<int:group_pk>/', UserRoleCreateView.as_view()),
    path('users/', UserView.as_view(), name='user'),
    path('users/all/', UserListView.as_view(), name='user_list'),
    path('users/<int:user_id>/', UserView.as_view(), name='user'),
    path('user-to-userrole/<int:user_pk>/<int:group_pk>/', UserToUserrole.as_view()),
    path('permission/',PermissionView.as_view()),
    path('userrole-permission/<int:group_pk>/<int:permission_pk>/',UserrolePermissionView.as_view()),
    path('userrole-permission/<int:group_pk>/',UserrolePermissionView.as_view()),


]
