from rest_framework import serializers, status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .models import AppUser, Group, File, AccessRequest
from . import utils
from django.utils import timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

from rest_framework import serializers
from .models import Group, File, GroupMember, AppUser

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class GroupMemberSerializer(serializers.ModelSerializer):
    # SlugRelatedField es un campo que representa la relación con otro modelo a través de un campo único (slug)
    user = serializers.SlugRelatedField(slug_field='username', queryset=AppUser.objects.all())
    group = serializers.SlugRelatedField(slug_field='id', queryset=Group.objects.all())
    class Meta:
        model = GroupMember
        fields = ['id', 'user', 'group', 'encrypted_symmetric_key']
        read_only_fields = ['id']

    def create(self, validated_data):
        group = validated_data['group']
        user = validated_data['user']

        # Add the member to the group
        group_member, created = GroupMember.objects.get_or_create(group=group, user=user)

        if not created:
            raise serializers.ValidationError(f"El usuario {user.username} ya es miembro del grupo.")

        # Additional logic to encrypt symmetric key
        if user.public_key is None or not user.public_key:
            raise serializers.ValidationError(f"El usuario {user.username} no tiene una clave pública válida.")

        private_key = utils.get_user_private_key(group.owner)
        symmetric_key = utils.decrypt_symmetric_key(private_key, group.encrypted_symmetric_key)
        encrypted_symmetric_key = utils.encrypt_symmetric_key(user.public_key, symmetric_key)
        group_member.encrypted_symmetric_key = encrypted_symmetric_key
        group_member.save()

        return group_member
    

class GroupSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username') # El propietario del grupo no puede ser modificado una vez creado
    members = serializers.SerializerMethodField() # SerializerMethodField es un campo de solo lectura que se puede utilizar para representar un campo que no es un campo de modelo, pero que se puede calcular a partir de otros campos

    class Meta: # La clase Meta es una clase interna que define metadatos sobre el serializador (como el modelo al que se refiere y los campos que se deben serializar)
        model = Group
        fields = ['id', 'group_name', 'owner', 'members']

    def get_members(self, obj):
        members = GroupMember.objects.filter(group=obj)
        return GroupMemberSerializer(members, many=True).data
    
    def create(self, validated_data):
        request = self.context.get('request')
        owner = request.user
        group = Group.objects.create(owner=owner, **validated_data)
        return group


class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'file_name', 'file', 'group', 'owner', 'ciphered', 'created_at', 'hash']
        read_only_fields = ['id', 'owner', 'created_at']

class UserRegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    email = serializers.EmailField(required=True)
    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Las contraseñas deben coincidir.")
        return data
    def create (self, validated_data):
        user = AppUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password1'])
        return user
    class Meta:
        model = AppUser
        fields = ['id', 'username', 'email', 'password1', 'password2', 'public_key']

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField()

    class Meta:
        model = AppUser
        fields = ['username', 'password']
"""
En general, en los serializadores de Django REST Framework (DRF), se espera que los campos de clave foránea (ForeignKey) sean enviados como identificadores (IDs) y no como objetos completos. 
Esto es porque el serializador necesita validar y deserializar los datos antes de procesarlos, y los IDs son mucho más manejables en este contexto.
"""
class AccessRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessRequest
        fields = ['id', 'requester', 'requested_group', 'created_at', 'status']
    
    def create(self, validated_data):
        requester = validated_data['requester']
        requested_group_id = validated_data['requested_group'].id
        requested_group = Group.objects.get(id=requested_group_id)
        access_request, created = AccessRequest.objects.get_or_create(
            requester = requester,
            requested_group = requested_group,
            defaults = {'status': AccessRequest.PENDING, 'created_at': timezone.now()}
        )
        if not created:
            return Response({"detail": "Ya existe una solicitud de acceso a este grupo."}, status=status.HTTP_200_OK)
        return access_request
    
class AccessRequestListSerializer(serializers.ModelSerializer):
    requester = serializers.SlugRelatedField(slug_field='username', queryset=AppUser.objects.all())
    requested_group = serializers.SlugRelatedField(slug_field='group_name', queryset=Group.objects.all())
    class Meta:
        model = AccessRequest
        fields = ['id', 'requester', 'requested_group', 'created_at', 'status']
        
# JWT Tokens can be customized by creating a custom serializer that inherits from TokenObtainPairSerializer. This custom serializer can be used to add custom claims to the token.
class ObtainTokenPairSerializer(TokenObtainPairSerializer):
    @classmethod # El decorador @classmethod se utiliza para definir un método de clase en Python. Un método de clase recibe la clase como primer argumento, al igual que un método de instancia recibe la instancia
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        return token