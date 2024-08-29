from datetime import timedelta
from time import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
import os
# Modelo de Usuario
class AppUser(AbstractUser):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    # Campo password: ya incluido en AbstractUser.
    # Campo is_active: indica si el usuario está activo o no. Ya incluido en AbastractUser
    # Los usuarios pueden ser propietarios de varios grupos y miembros de varios grupos
    member_groups = models.ManyToManyField('Group', related_name='member_users', blank=True)
    owned_groups = models.ManyToManyField('Group', related_name='group_owner', blank=True)
    # blank=True significa que el campo no es requerido
    # null=True significa que el campo puede ser nulo en la base de datos
    public_key = models.BinaryField(blank=True, null=True)
    # la clave privada no se almacena en la base de datos, se almacena en el lado del cliente
    private_key_path = models.TextField() #blank=True, null=True
    # La clave TOTP se utiliza para la autenticación de dos factores, obligatoria para los usuarios
    totp_key = models.CharField(max_length=16, blank=True, null=True)
    failed_attempts = models.IntegerField(default=0)
    lock_time = models.DateTimeField(null=True, blank=True)
    # Representación del usuario
    def __str__(self):
        return self.username

    def unlock(self):
        """ Desbloquea la cuenta automáticamente después de un período de tiempo. """
        if not self.is_active and self.lock_time and timezone.now() >= self.lock_time + timedelta(minutes=30):  # Desbloquea después de 30 minutos
            self.is_locked = False
            self.failed_attempts = 0
            self.lock_time = None
            self.save()

# Modelo de Grupo de compartición de archivos
class Group(models.Model):
    User = get_user_model()
    id = models.AutoField(primary_key=True)
    group_name = models.CharField(max_length=255, unique=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_groups_set')
    # members = models.ManyToManyField(User, related_name='member_groups_set')
    # Clave simétrica cifrada con la clave pública del propietario del grupo
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True)
    # Representación del grupo
    def __str__(self):
        return self.group_name
    # Añadir miembro al grupo
    def add_member(self, user):
        self.members.add(user)
        self.save()
    # Eliminar miembro del grupo (solamen   te el propietario del grupo puede eliminar miembros)
    def remove_member(self, user):
        self.members.remove(user)
        self.save()

def file_upload_to(instance, filename):
    # Construye la ruta del archivo basada en el nombre del grupo
    return os.path.join('uploads', f"group_{instance.group.group_name}", filename)

class GroupMember(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey(AppUser, on_delete=models.CASCADE, related_name='memberships')
    # el related_name es opcional, pero es útil para acceder a los miembros de un grupo desde un usuario. Por ejemplo, user.memberships.all()
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True)
    # Representación de la relación
    class Meta:
        unique_together = ('group', 'user') # Un usuario no puede ser miembro de un grupo más de una vez

    def __str__(self):
        return f'{self.user.username} in {self.group.group_name}' # Devuelve el nombre del usuario y el nombre del grupo

# Modelo de Archivo
class File(models.Model):
    User = get_user_model()
    file_name = models.CharField(max_length=100)
    file = models.FileField(upload_to=file_upload_to, blank=True, null=True) # Almacenar el archivo original
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='files')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_files')
    created_at = models.DateTimeField(auto_now_add=True)
    ciphered = models.BooleanField(default=False)
    # hash del archivo
    hash = models.CharField(max_length=64, blank=True, null=True) # blank y null para que el campo no sea requerido
    signature = models.BinaryField(blank=True, null=True) # Firma del archivo
    # Representación del archivo
    def __str__(self):
        return self.file_name

# Modelo de Solicitud de Acceso
class AccessRequest(models.Model):
    requester = models.ForeignKey(AppUser, on_delete=models.CASCADE, related_name='access_requests')
    requested_group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='access_requests')
    created_at = models.DateTimeField(auto_now_add=True)
    # Estado de la solicitud: puede ser aceptado, pendiente o rechazado (por defecto pendiente).
    # Definimos una lista de opciones para el estado de la solicitud: aceptado, pendiente o rechazado.
    ACCEPTED = 'accepted'; PENDING = 'pending'; REJECTED = 'rejected'
    STATUS_CHOICES = [ (ACCEPTED, 'accepted'), (PENDING, 'pending'), (REJECTED, 'rejected')]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PENDING, blank=True, null=True) # Usamos blank y null para que el campo no sea requerido
    # Estado de la solicitud
    def __str__(self):
        """Return a human readable representation of the model instance."""
        # La solicitud de acceso de {usuario} al grupo {grupo} está {estado} (el estado puede ser aceptado, pendiente o rechazado)
        return f'Access request from {self.user} to {self.requested_group.group_name} is {self.status}'

class OTP(models.Model):
    user = models.ForeignKey(AppUser, on_delete=models.CASCADE, related_name='otp')
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()
    # Representación del OTP
    def __str__(self):
        return self.otp