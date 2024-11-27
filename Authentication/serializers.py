from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User,Group,Permission



class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'  
    

        
class UserSerializer(serializers.ModelSerializer):
    # password = serializers.CharField(write_only=True)
    is_active = serializers.BooleanField(default=True)
    
    class Meta:
        model = User
        fields = ['id','username', 'password','email','is_active']
    def create(self, validated_data):
        # validated_data['is_active'] = True
        password = validated_data.pop('password')  
        user = User(**validated_data)
        user.set_password(password)  
        user.save()
        return user
    def update(self, instance, validated_data):
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)  # Hash the new password
        return super().update(instance, validated_data)
    

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'