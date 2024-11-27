from rest_framework.views import APIView,View
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User,Group,Permission
from rest_framework.permissions import IsAuthenticated,IsAdminUser,DjangoModelPermissions,AllowAny
from rest_framework.decorators import authentication_classes,permission_classes,api_view
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.decorators import permission_required
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from django.utils import timezone
from datetime import date,timedelta,datetime
from .serializers import *






class UserRoleCreateView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated,IsAdminUser]

    def get(self, request, group_pk):
        try:
            group = get_object_or_404(Group, pk=group_pk)
            users_in_group = group.user_set.all()
            user_data = [{'id': user.id, 'username': user.username} for user in users_in_group]
            return Response(user_data, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({"error": f"User role with pk {group_pk} not found."}, status=status.HTTP_404_NOT_FOUND)
    
    def post(self, request):
        serializer =GroupSerializer(data=request.data)
        if serializer.is_valid():
            role_name = serializer.validated_data['name']
            existing_role = Group.objects.filter(name=role_name).first()
            if existing_role:
                return Response({"error": "User role already exists."}, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()
            return Response({"message": "User role created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserRoleListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        user_roles = Group.objects.all()
        serializer = GroupSerializer(user_roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


class UserView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated,IsAdminUser ]
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get(self, request, user_id):
        user = self.get_user(user_id)
        if user:
            serializer = UserSerializer(user)
            return Response(serializer.data)
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self,request,user_id):
        user = self.get_user(user_id)
        if user:
            serializer = UserSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id):
        user = self.get_user(user_id)
        if user:
            user.is_active = False  # Logical deactivation of user account
            user.save()
            return Response({"message": "User deactivated"},status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_404_NOT_FOUND)
    
   
    
class UserListView(APIView):
    authentication_classes= [JWTAuthentication]
    permission_classes= [IsAuthenticated,IsAdminUser]
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


class UserToUserrole(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated,IsAdminUser]
    def put(self, request, user_pk, group_pk):
        try:
            user = User.objects.get(pk=user_pk)
            group = Group.objects.get(pk=group_pk)

            # Add user to the group
            group.user_set.add(user)

            # Grant permissions associated with the group to the user
            group_permissions = group.permissions.all()
            for permission in group_permissions:
                user.user_permissions.add(permission)

            return Response({"message": f"User {user_pk} added to user role {group_pk} successfully with group permissions granted."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": f"User with pk {user_pk} not found."}, status=status.HTTP_404_NOT_FOUND)
        except Group.DoesNotExist:
            return Response({"error": f"User role with pk {group_pk} not found."}, status=status.HTTP_404_NOT_FOUND)
    
    def delete(self, request, user_pk, group_pk):
        try:
            user = User.objects.get(pk=user_pk)
            group = Group.objects.get(pk=group_pk)

            # Remove user from the group
            group.user_set.remove(user)

            # Revoke permissions associated with the group from the user
            group_permissions = group.permissions.all()
            user_permissions = user.user_permissions.all()

            for permission in group_permissions:
                # Check if the user has the same permission from other groups
                permission_in_other_groups = Group.objects.filter(permissions=permission).exclude(pk=group_pk).exists()
                
                if permission_in_other_groups:
                    # Check if the user is included in other groups with the same permission
                    other_groups = Group.objects.filter(permissions=permission).exclude(pk=group_pk)
                    for other_group in other_groups:
                        if user in other_group.user_set.all():
                            # If the user is in another group with the same permission, skip revoking
                            continue

                # If the permission is not assigned via any other group or user isn't in those groups, revoke it
                if permission in user_permissions:
                    user.user_permissions.remove(permission)

            return Response({"message": f"User {user_pk} removed from user role {group_pk} successfully with permissions selectively revoked."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": f"User with pk {user_pk} not found."}, status=status.HTTP_404_NOT_FOUND)
        except Group.DoesNotExist:
            return Response({"error": f"User role with pk {group_pk} not found."}, status=status.HTTP_404_NOT_FOUND)
        

class PermissionView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated,IsAdminUser]
    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)
    
    def delete(self, request, permission_id):
        try:
            permission = Permission.objects.get(pk=permission_id)
        except Permission.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        permission.delete()
        return Response({"message": "Permission deleted"},status=status.HTTP_204_NO_CONTENT)
    
class UserrolePermissionView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated,IsAdminUser]
    def get(self, request, group_pk):
        try:
            group = Group.objects.get(pk=group_pk)
        except Group.DoesNotExist:
            return Response("Userrole not found", status=status.HTTP_404_NOT_FOUND)

        permissions = group.permissions.all()
        permission_data = []
        
        for permission in permissions:
            content_type = ContentType.objects.get_for_model(permission.content_type.model_class())
            permission_data.append({
                'id': permission.id,
                'codename': permission.codename,
                'name': permission.name,
                'content_type': {
                    'app_label': content_type.app_label,
                    'model': content_type.model
                }
            })

        return Response(permission_data, status=status.HTTP_200_OK)
    
    def post(self, request, group_pk, permission_pk):
        try:
            group = Group.objects.get(pk=group_pk)
        except Group.DoesNotExist:
            return Response("Userrole not found", status=status.HTTP_404_NOT_FOUND)

        try:
            permission = Permission.objects.get(pk=permission_pk)
        except Permission.DoesNotExist:
            return Response(f"Permission with ID {permission_pk} not found", status=status.HTTP_404_NOT_FOUND)

        # Add permission to the group
        group.permissions.add(permission)

        # Get users within the group
        users = group.user_set.all()

        # Assign the permission to each user
        for user in users:
            user.user_permissions.add(permission)

        return Response("Permission added to the userrole and users", status=status.HTTP_200_OK)
    
    def delete(self, request, group_pk, permission_pk):
        try:
            group = Group.objects.get(pk=group_pk)
        except Group.DoesNotExist:
            return Response("Userrole not found", status=status.HTTP_404_NOT_FOUND)

        try:
            permission = Permission.objects.get(pk=permission_pk)
        except Permission.DoesNotExist:
            return Response(f"Permission with ID {permission_pk} not found", status=status.HTTP_404_NOT_FOUND)
        other_groups_with_permission = Group.objects.filter(permissions=permission).exclude(pk=group_pk)

        if other_groups_with_permission.exists():
            users = group.user_set.all()
            for user in users:
                if permission in user.user_permissions.all():
                        # Check if the user is included in other groups with the same permission
                    other_groups = Group.objects.filter(permissions=permission).exclude(pk=group_pk)
                    for other_group in other_groups:
                        if user in other_group.user_set.all():
                                # If the user is in another group with the same permission, skip revoking
                            break
                    else:
                            # If the user is not in any other group with the same permission, revoke it
                        user.user_permissions.remove(permission)

                # Remove permission from the group
            group.permissions.remove(permission)
            
        else:
                # Remove permission from the group
            group.permissions.remove(permission)

                # Get users within the group
            users = group.user_set.all()

                # Revoke the permission from each user
            for user in users:
                user.user_permissions.remove(permission)

        return Response("Permission removed from the userrole and users", status=status.HTTP_200_OK)