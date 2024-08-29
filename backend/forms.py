from django import forms
from django.contrib.auth.decorators import login_required
from .models import AccessRequest
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import UserCreationForm
from .models import AppUser, Group, File, AccessRequest
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

# Definimos los formularios de la aplicación
# Usanos get_user_model para obtener el modelo de usuario personalizado, independientemente de si se ha cambiado el modelo de usuario en la configuración.
User = get_user_model()

# El formulario LoginForm es un formulario de inicio de sesión.
class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Username or Email', required=True)

    def clean(self):
        username_or_email = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username_or_email and password:
            # Verifica si el input es un email o un username
            if AppUser.objects.filter(email=username_or_email).exists():
                username = AppUser.objects.get(email=username_or_email).username
            else:
                username = username_or_email
            
            user = authenticate(username=username, password=password)
            if user is None:
                raise forms.ValidationError('Invalid credentials')
            else:
                self.cleaned_data['user'] = user
        return super().clean()
    
    
# El siguiente formulario es un formulario de registro de usuario.
# El formulario tiene cuatro campos: username, email, password y confirm_password.
# El campo confirm_password se utiliza para confirmar la contraseña.
# El formulario se utiliza para registrar un nuevo usuario en la aplicación.
class RegistrationForm(UserCreationForm):
    # username = forms.CharField(max_length=255)
    email = forms.EmailField(required=True)
    # password = forms.CharField(widget=forms.PasswordInput)
    # confirm_password = forms.CharField(widget=forms.PasswordInput)

    # La clase Meta se utiliza para definir el modelo del formulario.
    # En este caso, el modelo del formulario es AppUser.
    class Meta:
        model = User
        # Los campos del formulario son username, email, password y confirm_password.
        fields = ['username', 'email', 'password1', 'password2']
    # El método save se utiliza para guardar el usuario en la base de datos.
    def save(self, commit=True):
        # Ponemos commit=False para que no se guarde el usuario en la base de datos hasta que se llame al método save. Si no, se guardaría en cuanto se creara el usuario.
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

# El formulario GroupForm es un formulario que se utiliza para crear un grupo de compartición de archivos.
# El formulario tiene solo un campo: group_name.
# El campo group_name se utiliza para introducir el nombre del grupo.
# El par de claves se genera automáticamente cuando se crea el grupo usando OpenSSL y se almacena en la base de datos.
# La clave pública la genera la propia aplicación (usando OpenSSL) y se almacena en la base de datos.
# La clave pública se utiliza para cifrar los archivos que se comparten en el grupo.
class CreateGroupForm(forms.ModelForm):
    group_name = forms.CharField(max_length=255)
    # Validación del campo group_name.
    # Primero validamos que el campo group_name no esté vacío.
    # Luego se valida que el campo group_name no exista en la base de datos.
    # Si el group_name ya existe, se lanza un error.
    def clean_group_name(self):
        cleaned_data = super().clean()
        group_name = cleaned_data.get('group_name')
        if not group_name:
            raise forms.ValidationError('Group name is required')
        if Group.objects.filter(group_name=group_name).exists():
            raise forms.ValidationError('Group name already exists')
        return group_name
    # La clase Meta se utiliza para definir el modelo del formulario.
    # En este caso, el modelo del formulario es Group.
    class Meta:
        model = Group
        # Los campos del formulario son group_name.
        fields = ['group_name']


# El formulario AccessRequestForm se utiliza para solicitar acceso a un grupo de compartición de archivos.
# El formulario tiene dos campos: user y group.
# El campo user se utiliza para seleccionar el usuario que solicita acceso al grupo.
# El usuario debe ser el usuario autenticado.
# Obtenemos el usuario autenticado de la petición y lo añadimos al campo user del formulario.
@login_required
class AccessRequestForm(forms.ModelForm):
    user = forms.ModelChoiceField(queryset=AppUser.objects.all(), widget=forms.HiddenInput())
    group = forms.ModelChoiceField(queryset=Group.objects.all())
    class Meta:
        model = AccessRequest
        fields = ['user', 'group']
    # El método __init__ se utiliza para inicializar el formulario.
    # Añadimos el usuario autenticado al campo user del formulario.
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user')
        super().__init__(*args, **kwargs)
        self.fields['user'].initial = user
        self.fields['user'].widget = forms.HiddenInput()
    # El campo group lo rellenará el usuario con el nombre del grupo al que quiere solicitar acceso.
    # Validación del campo group.
    def clean_group(self):
        group_name = self.cleaned_data.get('group')
        user = self.cleaned_data.get('user')
        # Primero validamos que el grupo no pertenezca al usuario.
        if Group.objects.filter(group_name=group_name, owner=user).exists():
            raise forms.ValidationError('No puedes solicitar acceso al grupo que eres el propietario.')
        # Luego validamos que el usuario no sea ya miembro de ese grupo.
        if AccessRequest.objects.filter(requester=user, requested_group__group_name=group_name).exists():
            raise forms.ValidationError('Ya eres miemrbro de este grupo.')
        if AppUser.objects.filter(username=group_name).exists():
            raise forms.ValidationError('El nombre del grupo no puede ser el nombre de un usuario.')
        return group_name

# El formulario FileUploadForm se utiliza para subir un archivo a un grupo de compartición de archivos.
class FileUploadForm(forms.ModelForm):
    group = forms.ModelChoiceField(queryset=Group.objects.none(), required=True, label="Grupo de Subida")
    ciphered = forms.BooleanField(required=False, label="Cifrar archivo") # Añadimos un campo para cifrar el archivo
    class Meta:
        model = File
        fields = ['file', 'group']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user')
        initial_group = kwargs.pop('initial_group', None)
        super(FileUploadForm, self).__init__(*args, **kwargs)
        # Obtiene o crea el grupo personal para asegurarse de que siempre esté disponible
        personal_group, _ = Group.objects.get_or_create(group_name=f"{user.username}_personal_data", defaults={'owner': user})
        # Actualiza el queryset para incluir todos los grupos del usuario más su grupo personal
        self.fields['group'].queryset = Group.objects.filter(owner=user)
        if initial_group:
            self.fields['group'].initial = initial_group
        # Establece el grupo personal como opción inicial si no hay otros grupos
        if self.fields['group'].queryset.count() == 1:
            self.fields['group'].initial = personal_group.id
    
# El formulario FileDownloadForm se utiliza para descargar un archivo de un grupo de compartición de archivos.
class FileDownloadForm(forms.Form):
    file_name = forms.CharField(max_length=255)
    group_name = forms.CharField(max_length=255)
    def clean_file_name(self):
        file_name = self.cleaned_data.get('file_name')
        if not file_name:
            raise forms.ValidationError('File name is required')
        return file_name
    def clean_group_name(self):
        group_name = self.cleaned_data.get('group')
        if not group_name:
            raise forms.ValidationError('Group name is required')
        return group_name

# El formulario FileDeleteForm se utiliza para eliminar un archivo de un grupo de compartición de archivos.
class FileDeleteForm(forms.Form):
    file_name = forms.CharField(max_length=255)
    group_name = forms.CharField(max_length=255)
    def clean_file_name(self):
        file_name = self.cleaned_data.get('file_name')
        if not file_name:
            raise forms.ValidationError('File name is required')
        return file_name
    def clean_group_name(self):
        group_name = self.cleaned_data.get('group')
        if not group_name:
            raise forms.ValidationError('Group name is required')
        return group_name
    # Comprobamos que el usuario sea el propietario del grupo.
    def clean(self):
        cleaned_data = super().clean()
        file_name = cleaned_data.get('file_name')
        group_name = cleaned_data.get('group')
        user = self.user
        if not File.objects.filter(file_name=file_name, group_name__group_name=group_name, owner=user).exists():
            raise forms.ValidationError('You are not the owner of this file')
        return cleaned_data
# Añadimos un campo para seleccionar los nuevos miembros del grupo, pero solo debe mostrar los usuarios que no son miembros del grupo. Excluimos a los miembros actuales del grupo y al propietario del grupo.
# Para ello, importamos el grupo en el formulario y excluimos a los miembros actuales del grupo y al propietario del grupo.
# El formulario AddGroupMembersForm se utiliza para añadir nuevos miembros a un grupo de compartición de archivos.
class AddGroupMembersForm(forms.Form):
    members = forms.ModelMultipleChoiceField(queryset=User.objects.all(), widget=forms.CheckboxSelectMultiple, required=False, label="Select new members")
    def __init__(self, *args, **kwargs):
        group = kwargs.pop('group', None)
        super(AddGroupMembersForm, self).__init__(*args, **kwargs)
        if group:
            # Excluir al propietario y a los miembros actuales del grupo
            current_member_users = group.members.values_list('user', flat=True)
            # Excluimos al propietario del grupo y a los miembros actuales del grupo
            self.fields['members'].queryset = User.objects.exclude(id__in=current_member_users).exclude(id=group.owner.id)


# El formulario DeleteFileForm se utiliza para eliminar un archivo de un grupo de compartición de archivos.
class DeleteFileForm(forms.Form):
    file_name = forms.CharField(max_length=255)
    group_name = forms.CharField(max_length=255)
    def clean_file_name(self):
        file_name = self.cleaned_data.get('file_name')
        if not file_name:
            raise forms.ValidationError('File name is required')
        return file_name
    def clean_group_name(self):
        group_name = self.cleaned_data.get('group')
        if not group_name:
            raise forms.ValidationError('Group name is required')
        return group_name
    # Comprobamos que el usuario sea el propietario del grupo.
    def clean(self):
        cleaned_data = super().clean()
        file_name = cleaned_data.get('file_name')
        group_name = cleaned_data.get('group')
        user = self.user
        if not File.objects.filter(file_name=file_name, group_name__group_name=group_name, owner=user).exists():
            raise forms.ValidationError('You are not the owner of this file')
        return cleaned_data