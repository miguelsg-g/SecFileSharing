from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import AppUser, File, Group, AccessRequest

# Opcionalmente, puedes crear clases admin personalizadas para modificar cómo se muestran los modelos en el admin.
# Esto es útil si necesitas personalizar la interfaz de administración, por ejemplo, para mostrar campos adicionales en la lista de objetos, filtrar resultados, etc.

class AppUserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'is_active', )
    search_fields = ('username', 'email',)  # Campos por los que se puede buscar

class GroupAdmin(admin.ModelAdmin):
    list_display = ('group_name', 'owner',)
    search_fields = ('group_name',)

class FileAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'file', 'group','owner', 'created_at',)
    search_fields = ('name', 'group_name',)  # Nota el uso de doble subrayado para buscar en campos de modelos relacionados

class AccessRequestAdmin(admin.ModelAdmin):
    list_display = ('requester', 'requested_group',)
    search_fields = ('requester__username', 'requested_group__name',)

# Ahora, registra tus modelos y clases admin con el sitio de administración de Django.
admin.site.register(AppUser, AppUserAdmin)
admin.site.register(Group, GroupAdmin)
admin.site.register(File, FileAdmin)
admin.site.register(AccessRequest, AccessRequestAdmin)

# Si tienes más modelos que necesitas gestionar, repite el proceso creando una clase admin (si es necesario) y registrándola.

