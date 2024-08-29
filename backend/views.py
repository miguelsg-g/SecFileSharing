from datetime import timedelta
import logging
import subprocess
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail, EmailMessage
from django.contrib.auth import login, logout
from .forms import RegistrationForm, AccessRequestForm, AddGroupMembersForm, LoginForm, CreateGroupForm, FileUploadForm
from .models import AppUser, Group, File, AccessRequest, GroupMember, OTP
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponse, HttpResponseForbidden, FileResponse, JsonResponse
import os
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.conf import settings
from . import settings
from . import utils
from unidecode import unidecode
# importamos logger
from logging import getLogger
# Serialización de los modelos
from rest_framework import viewsets
from .serializers import UserSerializer, GroupSerializer, FileSerializer, AccessRequestSerializer, UserRegisterSerializer, LoginSerializer, GroupMemberSerializer, AccessRequestListSerializer, ObtainTokenPairSerializer
from rest_framework.views import APIView # Importa la clase APIView que se utiliza para crear vistas basadas en clases en Django REST framework.
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import AllowAny
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .decorators import auth_required
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication # Importa la autenticación de JWT de Django REST Framework Simple JWT
from django.views.decorators.csrf import ensure_csrf_cookie
# Importamos check_password para comprobar la contraseña del usuario
from django.contrib.auth.hashers import check_password
from django.middleware.csrf import get_token
import pyotp
from django.utils import timezone
import tempfile

MAX_FAILED_ATTEMPTS = 10  # Máximo número de intentos fallidos permitidos
User = get_user_model()
logger = getLogger(__name__)
# Las vistas son funciones que se utilizan para procesar las peticiones del usuario.
# Las vistas se utilizan para procesar las peticiones del usuario y devolver una respuesta.

# La vista de favicon se utiliza para renderizar el favicon de la aplicación, que es el icono que se muestra en la pestaña del navegador.
def favicon(request):
    return render(request, 'favicon.html')

# La vista de inicio se utiliza para renderizar la página de inicio.
@ensure_csrf_cookie
def index(request):
    return render(request, 'index.html')


def csrf_token_view(request):
    csrf_token = get_token(request)
    return JsonResponse({'csrfToken': csrf_token})

# La vista de inicio de sesión se utiliza para iniciar sesión en la aplicación.
def login_view(request):
    # Se añade un formulario de inicio de sesión a la petición.
    # request.POST or None se utiliza para inicializar el formulario con los datos de la petición.
    # Si es None, el formulario se inicializa vacío.
    form = LoginForm(request, data=request.POST or None)
    if form.is_valid():
        user = form.get_user()
        if user is not None:
            login(request, user)
            # Si el usuario es autenticado, redirigimos al usuario a la página de inicio.
            return redirect('personal_page')
        else:
            form.add_error('username', 'Invalid credentials')  
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form, 'error': form.non_field_errors()})


logger = logging.getLogger(__name__)

# TokenObtainPairView es una vista de Django REST framework Simple JWT que se utiliza para obtener un par de tokens de JWT a partir de las credenciales de un usuario (nombre de usuario y contraseña).
# Dichos tokens son el token de acceso y el token de refresco, y se envían al usuario en la respuesta.
# La vista de obtención de token se utiliza para obtener un token de autenticación para un usuario.
class JWTLoginView(TokenObtainPairView): 
    permission_classes = [AllowAny]
    serializer_class = ObtainTokenPairSerializer
    # imprimimos un mensaje en la consola para depurar con los datos del usuario
    # PENSAR CÓMO CAMBIAR ESTO PARA EVITAR LA TRANSMISIÓN DE LA CONTRASEÑA EN CLARO ENTRE EL FRONT Y EL BACK
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        otp_code = request.data.get('otp')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Comprueba si la cuenta del usuario está bloqueada, y si es así, la desbloquea automáticamente después de 30 minutos.
        user.unlock()

        if not user.is_active:
            return Response({'error': 'User account locked. Reset your password to reactivate it, or try again later.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            user.failed_attempts += 1
            user.save()
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.is_active = False
                user.lock_time = timezone.now()
                user.save()
                return Response({'error': 'User account locked. Reset your password to reactivate it.'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Si la contraseña es correcta, se restablece el número de intentos fallidos
            user.failed_attempts = 0
            user.save()
        # Validación de la autenticación de dos factores
        if otp_code:
            totp = OTP.objects.filter(user=User.objects.get(username=username), otp=otp_code, valid_until__gte=timezone.now()) 
            if totp:
                # Si se ha creado el objeto OTP, significa que el código es válido y se elimina de la base de datos
                totp.delete()
                return super().post(request, *args, **kwargs)
            else:
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Si no se proporciona el código OTP y las credenciales son válidas, se envía un correo electrónico con el código OTP.
            if not user.totp_key:
                user.totp_key = pyotp.random_base32() 
                user.save()
            otp = pyotp.TOTP(user.totp_key) # Genera un código OTP a partir de la clave secreta del usuario
            valid_until = timezone.now() + timedelta(minutes=5)
            otp_code = otp.now() # Genera el código OTP en función del tiempo actual.
            OTP.objects.create(user=user, otp=otp_code, valid_until=valid_until)
            # Envía un correo electrónico con el código OTP
            subject = 'SecFileSharingApp: One-Time Password'
            message = f'Your OTP is: {otp_code}. Valid for 5 minutes.'
            email = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [user.email])
            email.send()
            return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)


# La vista de registro se utiliza para registrar un nuevo usuario.
def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Creamos un nuevo usuario con los datos del formulario.
            # Lo guardamos con el método save, que devuelve una instancia del modelo.
            user = form.save()
            user.is_active = False
            # generamos su par de claves EN EL LADO DEL CLIENTE
            user.public_key, private_key = utils.generate_rsa_key_pair()
            utils.ensure_private_key_folder_exists()
            user.private_key_path = utils.save_private_key(user, private_key)
            file_path = utils.save_private_key(user, private_key)
            # Almacena la ruta del archivo de la clave privada en la base de datos
            user.private_key_path = file_path    
            user.save()
            # Enviamos un correo electrónico al usuario con un enlace para activar su cuenta.
            # Genera el token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            # Construye el enlace de verificación
            verify_link = request.build_absolute_uri(reverse('verify_email', args=[uid, token]))
            # Construye el mensaje de correo electrónico
            subject = 'Activate your account'
            message = render_to_string('email_verification.html', {'verify_link': verify_link})
            # Envía el correo electrónico
            email = EmailMessage(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            email.content_subtype = "html"  # Importante para interpretar el HTML
            email.send()
            # El enlace contiene un token (como parámetro en la URL) que se utiliza para activar la cuenta del usuario.
            # El token se genera automáticamente y se almacena en la base de datos.
            # El token se envía al usuario por correo electrónico.
            # El usuario debe hacer clic en el enlace para activar su cuenta.
            # Una vez que el usuario hace clic en el enlace, su cuenta se activa y puede iniciar sesión en la aplicación.
            # Redirigimos al usuario a una página para indicarle que su cuenta ha sido creada con éxito y que debe verificar su correo electrónico para activarla.
            return redirect('verification_request')
    else:
        form = RegistrationForm()
    # Renderizamos el formulario de registro

class RegisterView(APIView):
    permission_classes = [AllowAny] # Permite a los usuarios no autenticados acceder a esta vista
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                validated_data = serializer.validated_data
                # el uso de **validated_data permite pasar los datos validados como argumentos de palabra clave a la función create_, de manera equivalente a usar create_(username=validated_data['username'], email=validated_data['email'], etc.)
                user = User.objects.create(username=validated_data['username'], email=validated_data['email'])
                user.set_password(validated_data['password1'])
                user.is_active = False
                user.public_key, private_key = utils.generate_rsa_key_pair()
                utils.ensure_private_key_folder_exists()
                file_path = utils.save_private_key(user, private_key)
                # Almacena la ruta del archivo de la clave privada en la base de datos
                user.private_key_path = file_path
                user.save()

                # Enviamos un correo electrónico al usuario con un enlace para activar su cuenta.
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                # Construye el enlace de verificación con el token y el uid y la URL del frontend
                verify_link = f'http://localhost:3000/verify-email/{uid}/{token}/'
                # request.build_absolute_uri(reverse('verify_email', args=[uid, token]))
                
                subject = 'Activate your account'
                message = render_to_string('email_verification.html', {'verify_link': verify_link})
                email = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [user.email])
                email.content_subtype = "html"
                email.send()
                if user:
                    return Response({
                    "message": "Usuario creado correctamente. Por favor, verifica tu correo electrónico.",
                    'uid': uid, 'token': token}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error durante el registro: {str(e)}")
                return Response({"error": "Error interno del servidor"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # Si hay error 400, devolvemos los errores de validación
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# La vista de solicitud de verificación se utiliza para renderizar la página de solicitud de verificación de correo electrónico.
def verification_request_view(request):
    return render(request, 'verification_request.html')

def verify_email_view(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64)
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return redirect('personal_page')
    else:
        # implementar una página de error por token inválido
        return redirect(request, 'invalid_token.html')

# La vista de verificación de correo electrónico se utiliza para verificar el correo electrónico del usuario y activar su cuenta. Esta vista es de React.
class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        # Verifica si el token es válido
        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Correo electrónico verificado correctamente."}, status=status.HTTP_200_OK)
        return Response({"error": "Token inválido."}, status=status.HTTP_400_BAD_REQUEST)      

# La vista de cierre de sesión se utiliza para cerrar la sesión del usuario.
@login_required
def logout_view(request):
    logout(request)
    return redirect('login')

#@method_decorator(auth_required, name='dispatch')
class LogoutView(APIView):     
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            if not refresh_token:
                return Response({'error': 'Token de refresco no proporcionado'}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        # Si el token de refresco ya está en la lista negra, se lanza una excepción
        except TokenError as e:
            return Response({'error': 'Token inválido o expirado'}, status=status.HTTP_400_BAD_REQUEST)                
        except Exception as error:              
            return Response({'error': f'Error al cerrar sesión: {str(error)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

# La vista de inicio se utiliza para renderizar la página de inicio.
# login_required utiliza la cookie sessionid para comprobar si el usuario está autenticado.
@login_required
def dashboard_view(request):
    groups = Group.objects.all()  # Obtiene todos los grupos
    return render(request, 'dashboard.html', {'groups': groups})

# Diseñamos el dashboard pero en React en vez de en HTML y Django
# name='dispatch' es el nombre de la función que se ejecuta cuando se llama a la vista, que lo que hace es llamar al método dispatch de la clase APIView, cuya función es llamar al método correspondiente de la vista basándose en el método HTTP de la petición.
#@renderer_classes([JSONRenderer]) # renderer_classes se utiliza para especificar los renderizadores que se aplicarán a la vista.
@method_decorator(auth_required, name='dispatch')
class DashboardView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            groups = Group.objects.all()
            serializer = GroupSerializer(groups, many=True)
            serializer_user = UserSerializer(request.user, many=False)
            return Response({'groups': serializer.data, 'user': serializer_user.data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching dashboard data: {e}")
            return Response({'error': 'Error fetching data'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de página personal se utiliza para renderizar la página personal del usuario.
@login_required
def personal_page_view(request):
    user = request.user
    # Obtiene los grupos a los que pertenece el usuario sin usar el campo member_groups
    user_groups = Group.objects.filter(members__user=user)
    for group in user_groups:
        print(group.group_name)
    user_owned_groups = Group.objects.filter(owner=request.user)
    return render(request, 'personal_page.html', {'user_groups': user_groups, 'user_owned_groups': user_owned_groups})

# Diseñamos la vista de la página personal pero en React en vez de en HTML y Django
# @method_decorator(auth_required, name='dispatch')
# @renderer_classes((TemplateHTMLRenderer, JSONRenderer))
class PersonalPageView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def get(self, request):
        try:
            user = request.user
            user_groups = Group.objects.filter(members__user=user)
            user_owned_groups = Group.objects.filter(owner=user)
            serializer_user = UserSerializer(user, many=False)
            serializer_user_groups = GroupSerializer(user_groups, many=True)
            serializer_user_owned_groups = GroupSerializer(user_owned_groups, many=True)
            return Response({'user': serializer_user.data, 
                             'user_groups': serializer_user_groups.data, 
                             'user_owned_groups': serializer_user_owned_groups.data
                             }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching personal page data: {e}")
            return Response({'error': 'Error fetching data'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de detalle de grupo se utiliza para renderizar la página de detalle de un grupo.
@login_required
def group_detail_view(request, group_id):
    group = get_object_or_404(Group, pk=group_id)
    files = group.files.all()
    if Group.objects.filter(members__user=request.user).exists():
        is_member = True
    else:
        is_member = False
    if group.owner != request.user and not Group.objects.filter(members__user=request.user).exists():
        messages.error(request, f"No tienes permiso para ver el grupo {group.group_name}.")
        return redirect('personal_page')
    if group.group_name == f"{request.user.username}_personal_data":
        messages.info(request, "Este es tu grupo personal. Solo tú puedes ver los archivos que subas aquí.")
        is_personal_group = True
    else:
        is_personal_group = False
    if not files:
        messages.info(request, "No hay archivos en este grupo.")
    is_owner = (group.owner == request.user)
    can_upload = is_owner
    if can_upload:
        messages.info(request, "Puedes subir archivos a este grupo.")
    else:
        messages.info(request, "No puedes subir archivos a este grupo.")
    return render(request, 'group_detail.html', {'group': group, 'files': files, 'can_upload': can_upload, 'is_personal_group': is_personal_group, 'is_member': is_member})


class GroupDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, group_id):
        group = get_object_or_404(Group, id=group_id)
        files = File.objects.filter(group=group)

        group_serializer = GroupSerializer(group)
        file_serializer = FileSerializer(files, many=True)

        if group.owner != request.user and not Group.objects.filter(members__user=request.user).exists():
            return Response({'error': 'No tienes permiso para ver este grupo.'}, status=status.HTTP_403_FORBIDDEN)

        can_upload = (request.user == group.owner) # Solo el propietario del grupo puede subir archivos
        is_member = group.members.filter(user=request.user).exists()

        user_serializer = UserSerializer(request.user)

        return Response({
            'user': user_serializer.data,
            'group': group_serializer.data,
            'files': file_serializer.data,
            'can_upload': can_upload,
            'is_member': is_member,
            'is_personal_group': group.group_name.endswith('_personal_data')
        }, status=status.HTTP_200_OK)

class GroupViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

# La vista de detalle de archivo se utiliza para renderizar la página de detalle de un archivo.
@login_required
def file_detail_view(request, file_id):
    file = File.objects.get(pk=file_id)
    return render(request, 'file_detail.html', {'file': file})

# La vista de los grupos a los que pertenece el usuario se utiliza para renderizar la página de grupos a los que pertenece el usuario.
@login_required
def group_view(request):
    groups = request.user.member_groups.all()
    return render(request, 'groups.html', {'groups': groups})

# La vista de compartir archivo se utiliza para compartir un archivo con un grupo.
@login_required
def access_request_view(request):
    if request.method == 'POST':
        form = AccessRequestForm(request.POST, user = request.user)
        if form.is_valid():
            access_request = form.save(commit=False)
            access_request.requester = request.user
            access_request.save()
            # Enviamos notificación al propietario del grupo con la solicitud de acceso.
            # El propietario del grupo recibe una notificación en la aplicación y por correo electrónico.
            owner = access_request.requested_group.owner
            subject = f"Solicitud de acceso al grupo {access_request.requested_group.group_name}"
            message = render_to_string('/access_request_email.html', {
                'requester': access_request.requester,
                'requested_group': access_request.requested_group,
                'owner': owner,
                'access_request': access_request,
                'accept_url': reverse('accept_access_request', args=[access_request.id]),
                'reject_url': reverse('reject_access_request', args=[access_request.id]),
            })
            # Usamos la función send_mail para enviar el correo electrónico con los parámetros: asunto, mensaje, correo electrónico de origen, lista de correos electrónicos de destino.
            # La dirección de correo electrónico de origen es el correo electrónico HAY QUE CAMBIARLA por la del administrador de la aplicación.
            send_mail(subject, message, access_request.requester.email, [owner.email])
            return redirect('personal_page')
    else:
        form = AccessRequestForm(user=request.user)
    return render(request, 'access_request.html', {'form': form})

# La vista de solicitud de acceso se utiliza para solicitar acceso a un grupo. Esta vista es de React.
class AccessRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, group_id):
        try:
            requested_group = get_object_or_404(Group, id=group_id)
            # Si el grupo es personal, no se puede solicitar acceso
            if requested_group.group_name == f"{request.user.username}_personal_data":
                return Response({'error': 'No puedes solicitar acceso a tu grupo personal.'}, status=status.HTTP_400_BAD_REQUEST)
            # Si el usuario ya es miembro del grupo, no se puede solicitar acceso
            if requested_group.members.filter(user=request.user).exists():
                return Response({'error': 'Ya eres miembro de este grupo.'}, status=status.HTTP_400_BAD_REQUEST)
            # Si ya hay una solicitud de acceso pendiente, no se solicita y se avisa al usuario
            if AccessRequest.objects.filter(requested_group=requested_group, requester=request.user, status=AccessRequest.PENDING).exists():
                return Response({'message': 'Ya tienes una solicitud de acceso pendiente a este grupo.'}, status=status.HTTP_200_OK)
            data = {
                'requested_group': requested_group.id,
                'requester': request.user.id
            }

            serializer = AccessRequestSerializer(data=data, context={'request': request})
            if serializer.is_valid():
                access_request = serializer.save()
                owner = access_request.requested_group.owner
                subject = f"Solicitud de acceso al grupo {access_request.requested_group.group_name}"
                message = render_to_string('access_request_email.html', {
                    'requester': access_request.requester,
                    'requested_group': access_request.requested_group,
                    'owner': owner,
                    'access_request': access_request,
                    # La URL tiene que ser: http://localhost:8000/api/handle_access_request/<access_request_id>/<status>
                    'accept_url': request.build_absolute_uri(reverse('handle_access_request', args=[access_request.id, AccessRequest.ACCEPTED])),
                    'reject_url': request.build_absolute_uri(reverse('handle_access_request', args=[access_request.id, AccessRequest.REJECTED])),
                })
                # el correo se enviará desde la dirección de correo de la aplicación
                # Cargar las variables de entorno desde el archivo .env
                send_mail(subject, '', settings.EMAIL_HOST_USER, [owner.email], html_message=message)
                return Response({'message': 'Solicitud de acceso enviada correctamente.'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error enviando la solicitud de acceso: {str(e)}")
            return Response({'error': f'Error enviando la solicitud de acceso: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de añadir miembros al grupo se utiliza para añadir miembros a un grupo.
@method_decorator(auth_required, name='dispatch')
class HandleAccessRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, request_id, action):
        try:
            access_request = get_object_or_404(AccessRequest, id=request_id)
            if access_request.status != AccessRequest.PENDING and (action == AccessRequest.ACCEPTED or access_request.status == AccessRequest.REJECTED):
                return Response({'error': 'Solicitud de acceso ya procesada.'}, status=status.HTTP_400_BAD_REQUEST)
            if action == AccessRequest.ACCEPTED:
                access_request.status = AccessRequest.ACCEPTED
                GroupMember.objects.create(user=access_request.requester, group=access_request.requested_group)
            elif action == AccessRequest.REJECTED:
                access_request.status = AccessRequest.REJECTED
            else:
                return Response({'error': 'Estado de solicitud inválido.'}, status=status.HTTP_400_BAD_REQUEST)  
            access_request.save()
            # Envía un email al usuario que solicitó el acceso al grupo para informarle de que su solicitud ha sido aceptada.
            owner = access_request.requested_group.owner
            subject = f"Solicitud de acceso al grupo {access_request.requested_group.group_name}"
            message = render_to_string('access_request_result_email.html', {
                'requester': access_request.requester,
                'requested_group': access_request.requested_group,
                'status': 'aceptado' if action == 'accepted' else 'rechazado',
                'owner': owner,
            })
            send_mail(subject, '', settings.EMAIL_HOST_USER, [access_request.requester.email], html_message=message)
            # Se redirige al frontend a la página de detalle del grupo mediante el ID del grupo. Si el usuario no está autenticado, se le redirige a la página de inicio de sesión.
            group = access_request.requested_group
            return Response({'message': 'Solicitud de acceso procesada correctamente.', 'group_id': group.id}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error manejando la solicitud de acceso: {e}")
            return Response({'error': 'Error manejando la solicitud de acceso'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# La vista de una lista de peticiones de acceso se utiliza para renderizar la página de una lista de peticiones de acceso.
@method_decorator(auth_required, name='dispatch')
class AccessRequestsListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, group_id):
        try:
            group = get_object_or_404(Group, id=group_id)
            if group.owner != request.user:
                return Response({'error': 'No tienes permiso para ver estas solicitudes.'}, status=status.HTTP_403_FORBIDDEN)
            requests = AccessRequest.objects.filter(requested_group=group)
            serializer = AccessRequestListSerializer(requests, many=True)
            print(serializer.data)
            return Response({'requests': serializer.data, 'group': GroupSerializer(group).data, 'user': UserSerializer(request.user).data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching access requests: {e}")
            return Response({'error': 'Error fetching access requests'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de aceptar solicitud de acceso se utiliza para aceptar una solicitud de acceso a un grupo.
@login_required
def accept_access_request_view(request, access_request_id):
    access_request = AccessRequest.objects.get(id=access_request_id)
    access_request.status = AccessRequest.STATUS_ACCEPTED
    access_request.save()
    return redirect('group_detail', group_id=access_request.requested_group.id)

# La vista de rechazar solicitud de acceso se utiliza para rechazar una solicitud de acceso a un grupo.
@login_required
def reject_access_request_view(request, access_request_id):
    access_request = AccessRequest.objects.get(id=access_request_id)
    access_request.status = AccessRequest.STATUS_REJECTED
    access_request.save()
    return redirect('group_detail', group_id=access_request.requested_group.id)

# La vista de creación de grupo se utiliza para crear un nuevo grupo.
@login_required
def create_group_view(request):
    if request.method == 'POST':
        form = CreateGroupForm(request.POST)
        if form.is_valid():
            group = form.save(commit=False)
            group.owner = request.user
            group.save()
            messages.success(request, "Grupo creado exitosamente.")  # Muestra un mensaje de éxito
            return redirect('personal_page')
    else:
        form = CreateGroupForm()
    return render(request, 'create_group.html', {'form': form})

# Vista de creación de grupo integrada con React para crear un nuevo grupo.
@method_decorator(auth_required, name='dispatch')
class CreateGroupView(APIView):
    def post(self, request):
        try:
            serializer = GroupSerializer(data=request.data, context={'request': request}) # context={'request': request} se utiliza para pasar la petición al serializador
            if serializer.is_valid():
                group = serializer.save()
                return Response({'message': 'Grupo creado exitosamente.', 'group': group}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creando el grupo: {e}")
            return Response({'error': 'Error creando el grupo'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de subida de archivo se utiliza para subir un archivo a un grupo.
@login_required
def upload_file_view(request, group_id=None):
    # al poner group_id=None, se indica que el parámetro es opcional
    group = None
    if group_id:
        group = get_object_or_404(Group, pk=group_id)
        if group.owner != request.user:
                messages.error(request, "No tienes permiso para subir archivos a este grupo.")
                return redirect('personal_page')
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            file_instance = form.save(commit=False)
            if request.FILES['file'].file.closed:
                    request.FILES['file'].open()
            file_instance.file_name = unidecode(request.FILES['file'].name).replace(" ", "_").replace("(", "").replace(")", "")
            file_instance.group = form.cleaned_data['group']
            file_instance.owner = request.user
            # Verifica si el grupo seleccionado es el grupo personal
            # Obtiene el grupo seleccionado en el formulario
            selected_group = form.cleaned_data['group']
            if selected_group.owner != request.user:
                messages.error(request, "No tienes permiso para subir archivos a este grupo.")
                return redirect('group_detail', group_id=group.id, files=selected_group.files.all())
            personal_group_name = f"{request.user.username}_personal_data"
            if selected_group.group_name == personal_group_name:
                # Obtiene o crea el grupo personal si se seleccionó
                group, _ = Group.objects.get_or_create(group_name=personal_group_name, defaults={'owner': request.user})
                # Se crea la carpeta para el grupo personal
                utils.ensure_group_folder_exists(group)
            else:
                # Si se seleccionó otro grupo, lo utiliza directamente
                group = selected_group
            # da error porque el campo File.file no reconoce el archivo cifrado como un archivo
            if form.cleaned_data['ciphered']:
                # symmetric_key =  utils.get_or_generate_symmetric_key(group=group, user=request.user, create=True) # utils.decrypt_symmetric_key(private_key, group.encrypted_symmetric_key)
                # encrypted_file_data = utils.encrypt_file(request.FILES['file'], symmetric_key)
                file_instance.ciphered = True
                file, _ = utils.save_encrypted_file(file_instance, group, user=request.user)
                # Eliminar el archivo original del sistema de archivos
                request.FILES['file'].file.close()
                # comprobamos que file_instance y file no sean lo mismo mirando si ha cambiado el nombre del archivo
                if file_instance.file.name == file.name:
                    messages.error(request, "Error al subir el archivo. No se ha podido cifrar correctamente.")
                    return redirect('group_detail', group_id=group.id)
                file_instance.file.delete()
                file_instance.file = file
            else:
                file_instance.file = request.FILES['file']
                file_instance.ciphered = False
            try:
                file_instance.save()
                messages.success(request, "Archivo subido correctamente.")
                return redirect('group_detail', group_id=group.id)
            except UnicodeEncodeError as e:
                # Manejo de la excepción UnicodeEncodeError
                messages.error(request, "Error al subir el archivo.")
                logger.error(f"Error al guardar el archivo: {e}")
                return redirect('group_detail', group_id=group.id)
        else:
            messages.error(request, "Error al subir el archivo.")
    else:
        form = FileUploadForm(user=request.user, initial_group=group)
    return render(request, 'upload_file.html', {'form': form})

# La vista de subida de archivo integrada con React se utiliza para subir un archivo a un grupo.
# @method_decorator(auth_required, name='dispatch')
class UploadFileView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            user = request.user

            file = request.FILES.get('file')
            if not file:
                return Response({"error": "No se ha seleccionado ningún archivo."}, status=status.HTTP_400_BAD_REQUEST)
            
            group_name = data.get('group')
            if not group_name:
                return Response({"error": "No se ha seleccionado ningún grupo."}, status=status.HTTP_400_BAD_REQUEST)
            
            ciphered = data.get('ciphered', False) == 'true'

            personal_group_name = f"{user.username}_personal_data"
            if group_name == personal_group_name:
                group, _ = Group.objects.get_or_create(group_name=personal_group_name, defaults={'owner': user})
                group.owner = user # Añade el propietario al grupo personal
                # Hacemos que el grupo personal no pueda modificar su propietario
                group.save()
                utils.ensure_group_folder_exists(group)
            else:
                try:
                    group = Group.objects.get(group_name=group_name)
                except Group.DoesNotExist:
                    return Response({"error": "Grupo no encontrado."}, status=status.HTTP_404_NOT_FOUND)

                if group.owner != user:
                    return Response({"error": "No tienes permiso para subir archivos a este grupo."}, status=status.HTTP_403_FORBIDDEN)

            # Crear un archivo temporal para el escaneo
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in file.chunks():
                    temp_file.write(chunk)
                temp_file_path = temp_file.name  # Obtener la ruta del archivo temporal
            # Escaneo de virus usando ClamAV
            # Antes hay que moverse a la carpeta donde se encuentra ClamAV
            os.chdir(settings.CLAMAV_PATH)
            scan_result = subprocess.run([settings.CLAMAV_COMMAND, temp_file_path], capture_output=True)

            if b'FOUND' in scan_result.stdout:
                return Response({"error": "Archivo infectado. No se ha subido."}, status=status.HTTP_400_BAD_REQUEST)
            # Si el archivo no está infectado, se sube al grupo
            # Prepare the file
            file_instance = File(
                owner=user,
                group=group,
                file=file,
                file_name=unidecode(file.name).replace(" ", "_").replace("(", "").replace(")", ""),
                ciphered=ciphered
            )
            # signature = utils.generate_signature(utils.get_user_private_key(user), file_instance.file.read())
            # file_instance.signature = signature
            if ciphered:
                file, _ = utils.save_encrypted_file(file_instance, group, user=user)
                if file_instance.file.name == file.name:
                    return Response({"error": "Error al subir el archivo. No se ha podido cifrar correctamente."}, status=status.HTTP_400_BAD_REQUEST)
                file_instance.file.delete()
                file_instance.file = file

            # Save the file
            file_instance.save()
            return Response({"message": "Archivo subido correctamente."}, status=status.HTTP_201_CREATED)

        except UnicodeEncodeError as e:
            logger.error(f"Error al guardar el archivo: {e}")
            return Response({"error": "Error al subir el archivo."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Error al subir el archivo: {e}")
            return Response({"error": "Error al subir el archivo."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # get se utiliza en este caso para obtener los grupos a los que pertenece el usuario
    def get(self, request):
        user = request.user
        groups = Group.objects.filter(owner=user)
        personal_group_name = f"{user.username}_personal_data"
        personal_group, created = Group.objects.get_or_create(group_name=personal_group_name, defaults={'owner': user})
        if created:
            utils.ensure_group_folder_exists(personal_group)
        group_serializer = GroupSerializer(groups, many=True)
        return Response({"groups": group_serializer.data}, status=status.HTTP_200_OK)

@login_required
def add_group_members_view(request, group_id):
    group = get_object_or_404(Group, pk=group_id)
    if group.owner != request.user:
        messages.error(request, "No tienes permiso para añadir miembros a este grupo.")
        return redirect('group_detail', group_id=group_id)
    form = AddGroupMembersForm(request.POST or None,group=group)
    if request.method == 'POST' and form.is_valid():
        members = form.cleaned_data['members']
        for member in members:
            if not group.members.filter(user=member).exists():
                GroupMember.objects.create(group=group, user=member)
                # private_key = utils.get_user_private_key(group.owner)
                # symmetric_key = utils.decrypt_symmetric_key(private_key, group.encrypted_symmetric_key)
                # encrypted_symmetric_key = utils.encrypt_symmetric_key(member.public_key, symmetric_key)
                # group_member = GroupMember.objects.get(group=group, user=member)
                # group_member.encrypted_symmetric_key = encrypted_symmetric_key
                # group_member.save()
            user = User.objects.get(username=member)
            if user.public_key is None or not user.public_key:
                messages.error(request, f"El usuario {member} no tiene una clave pública válida.")
                return redirect('add_group_members', group_id=group_id)
            # if user != group.owner and not group.members.filter(id=user.id).exists():
            #     print("Segundo intento de añadir miembro al grupo.")
            #     private_key = utils.get_user_private_key(group.owner)
            #     symmetric_key = utils.decrypt_symmetric_key(private_key, group.encrypted_symmetric_key)
            #     GroupMember.objects.create(group=group, user=user, encrypted_symmetric_key=utils.encrypt_symmetric_key(user.public_key, symmetric_key))
            messages.success(request, "Miembros añadidos correctamente.")
            return redirect('group_detail', group_id=group_id)
    else:
        form = AddGroupMembersForm(group=group)
    return render(request, 'add_group_members.html', {'form': form, 'group': group})

# La vista de añadir miembros a un grupo integrada con React se utiliza para añadir miembros a un grupo.
class AddGroupMembersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, group_id):
        group = get_object_or_404(Group, pk=group_id)
        if group.owner != request.user:
            return Response({"error": "No tienes permiso para añadir miembros a este grupo."}, status=status.HTTP_403_FORBIDDEN)

        users = AppUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, group_id):
        try:
            group = get_object_or_404(Group, pk=group_id)
            if group.owner != request.user:
                return Response({"error": "No tienes permiso para añadir miembros a este grupo."}, status=status.HTTP_403_FORBIDDEN)
            
            members_data = request.data.get('members', [])
            errors = []
            for username in members_data:
                user = AppUser.objects.get(username=username)
                if not GroupMember.objects.filter(group=group, user=user).exists():
                    serializer = GroupMemberSerializer(data={'group': group.id, 'user': user.username})
                    if serializer.is_valid():
                        serializer.save()
                    else:
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            # Comprobamos si ha habido errores
            if errors != []:
                return Response({"message": "Algunos miembros no se pudieron añadir.", "errors": errors}, status=status.HTTP_207_MULTI_STATUS)
            return Response({"message": "Miembros añadidos correctamente."}, status=status.HTTP_201_CREATED)
        except Group.DoesNotExist:
            return Response({"error": "Grupo no encontrado."}, status=status.HTTP_404_NOT_FOUND)
        except AppUser.DoesNotExist:
            return Response({'error': 'Usuario no encontrado.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error al añadir miembros: {e}")
            return Response({"error": "Error al añadir miembros."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, group_id):
        try:
            group = Group.objects.get(id=group_id)
            members = group.members.values_list('user__id', flat=True)
            users = AppUser.objects.exclude(id__in=members).exclude(id=group.owner.id)
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=200)
        except Group.DoesNotExist:
            return Response({'error': 'Grupo no encontrado.'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

# Vista para solicitud de acceso de un usuario a un grupo
@login_required
def request_access_view(request, group_id):
    group = get_object_or_404(Group, pk=group_id)
    access_request = AccessRequest.objects.create(requester=request.user, requested_group=group)
    access_request.status = AccessRequest.PENDING
    access_request.save()
    # Aquí podrías implementar el envío de una notificación al propietario del grupo
    for user in User.objects.all():
        if group.group_name == f"{user.username}_personal_data":
            messages.error(request, "No puedes solicitar acceso a un grupo personal.")
            return redirect('dashboard')        
    subject = 'Access Request'
    message = render_to_string('access_request_email.html', {
        'user': request.user,
        'group': group,
        'accept_url': request.build_absolute_uri(
            reverse('manage_access_request', kwargs={'request_id': access_request.id, 'action': 'accept'})),
        'reject_url': request.build_absolute_uri(
            reverse('manage_access_request', kwargs={'request_id': access_request.id, 'action': 'reject'}))
    })
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [group.owner.email])
    messages.success(request, "Access request sent successfully.")
    return redirect('dashboard')

# Vista para aceptar/rechazar solicitudes de acceso (propietario)
@login_required
def manage_access_requests_view(request, request_id, action):
    access_request = get_object_or_404(AccessRequest, id=request_id)
    if action == 'accept':
        GroupMember.objects.create(group=access_request.group, user=access_request.user)
        access_request.status = AccessRequest.ACCEPTED
        access_request.save()
        # Envío de correo electrónico de confirmación al solicitante
        send_mail(
            'Access Request Approved',
            'Your request to access the group has been approved.',
            settings.DEFAULT_FROM_EMAIL,
            [access_request.user.email]
        )
        messages.success(request, "Access request approved.")
    elif action == 'reject':
        send_mail(
            'Access Request Rejected',
            'Your request to access the group has been rejected.',
            settings.DEFAULT_FROM_EMAIL,
            [access_request.user.email]
        )
        messages.info(request, "Access request rejected.")
        access_request.status = AccessRequest.REJECTED
    return redirect('group_detail', group_id=access_request.group.id)

# La vista de descarga de archivo se utiliza para descargar un archivo de un grupo.
# La descarga se realiza mediante un enlace de descarga.
# Desencriptamos el archivo antes de enviarlo al usuario
@login_required
def download_file_view(request, file_id):
    file = get_object_or_404(File, pk=file_id)
    user = request.user
    if Group.objects.filter(members__user=request.user).exists():
        is_member = True
    else:
        is_member = False
    if is_member==False and file.owner != request.user:
        return HttpResponseForbidden("No tienes permiso para descargar este archivo.")
    if not file.ciphered:
        with open(file.file.path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/force-download")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file.file.path)
            return response
    elif file.ciphered and file.file and file.group.encrypted_symmetric_key:
        # Obtenemos la clave privada del usuario
        private_key = utils.get_user_private_key(request.user)
        if not private_key:
            messages.error(request, "No se ha encontrado la clave privada del usuario.")
            return redirect('group_detail', group_id=file.group.id)
        if file.group.encrypted_symmetric_key is None:
            utils.get_or_generate_symmetric_key(group=file.group, user=request.user, create=True)
        # Obtenemos la clave simétrica cifrada del archivo
        if user == file.owner:
            symmetric_key = utils.decrypt_symmetric_key(private_key, file.group.encrypted_symmetric_key)
        else:
            group_member = Group.objects.get(group_name=file.group.group_name, members__user=request.user)
            if group_member.encrypted_symmetric_key is None:
                private_key = utils.get_user_private_key(file.group.owner)
                symmetric_key = utils.decrypt_symmetric_key(private_key, file.group.encrypted_symmetric_key)
                group_member.encrypted_symmetric_key = utils.encrypt_symmetric_key(user.public_key, symmetric_key)
                group_member.save()
            else:
                symmetric_key = utils.decrypt_symmetric_key(private_key, group_member.encrypted_symmetric_key)
        # desencriptamos el archivo
        # Obtenemos la ruta del archivo cifrado sin usar el campo file del modelo File
        # Obtenemos el nombre del archivo en el sistema de archivos, que si tiene espacios en blanco, se reemplazan por guiones bajos, y si tiene caracteres especiales, se eliminan
        # Si tiene tildes, se eliminan
        file_uploaded_name = file.file_name.replace(" ", "_").replace(" ", "_").replace("(", "").replace(")", "")
        file_uploaded_name = unidecode(file_uploaded_name)
        file_path = os.path.join(settings.UPLOADS_DIR, f"group_{file.group.group_name}", f"{file_uploaded_name}.enc")
        decrypted_file = utils.decrypt_file(file_path, symmetric_key)
        # Quitamos la extensión .enc del nombre del archivo
        # No guardamos el archivo desencriptado en el sistema de archivos, ya que se envía directamente al usuario
        # Como el archivo descifrado no está en el sistema de archivos, lo enviamos como un adjunto
        response = HttpResponse(decrypted_file, content_type="application/force-download")
        response['Content-Disposition'] = 'inline; filename=' + decrypted_file.field_name
        return response
    messages.error(request, "No se ha encontrado el archivo.")
    return redirect('group_detail', group_id=file.group.id)

class DownloadFileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, file_id):
        try:
            file = get_object_or_404(File, pk=file_id)
            user = request.user
            is_member = GroupMember.objects.filter(group=file.group, user=user).exists() or file.owner == user

            if not is_member:
                return Response({"error": "No tienes permiso para descargar este archivo."}, status=status.HTTP_403_FORBIDDEN)
            
            if not file.ciphered:
                with open(file.file.path, 'rb') as fh:
                    response = FileResponse(fh, as_attachment=True, filename=file.file_name)
                    return response
            elif file.ciphered and file.file and file.group.encrypted_symmetric_key:
                private_key = utils.get_user_private_key(request.user)
                if not private_key:
                    return Response({"error": "No se ha encontrado la clave privada del usuario."}, status=status.HTTP_400_BAD_REQUEST)
                
                if file.group.encrypted_symmetric_key is None:
                    utils.get_or_generate_symmetric_key(group=file.group, user=user, create=True)
                
                if user == file.owner:
                    symmetric_key = utils.decrypt_symmetric_key(private_key, file.group.encrypted_symmetric_key)
                else:
                    group_member = GroupMember.objects.get(group=file.group, user=request.user)
                    if group_member.encrypted_symmetric_key is None:
                        private_key = utils.get_user_private_key(file.group.owner)
                        symmetric_key = utils.decrypt_symmetric_key(private_key, file.group.encrypted_symmetric_key)
                        group_member.encrypted_symmetric_key = utils.encrypt_symmetric_key(user.public_key, symmetric_key)
                        group_member.save()
                    else:
                        symmetric_key = utils.decrypt_symmetric_key(private_key, group_member.encrypted_symmetric_key)
                
                file_uploaded_name = unidecode(file.file_name.replace(" ", "_").replace("(", "").replace(")", ""))
                if file.ciphered:
                    file_uploaded_name = f"{file_uploaded_name}.enc"
                file_path = os.path.join(settings.UPLOADS_DIR, f"group_{file.group.group_name}", file_uploaded_name)
                decrypted_file = utils.decrypt_file(file_path, symmetric_key)

                # Antes de enviar el archivo al usuario, se verifica la firma del archivo
                # Si la firma es válida, se envía el archivo al usuario, de lo contrario, se envía un mensaje de error, ya que el archivo puede contener malware
                # file_data = decrypted_file.read()
                # if not utils.verify_signature(public_key=file.group.owner.public_key, file_data=file_data, signature=file.signature):
                #     return Response({"error": "Firma del archivo no válida. El archivo ha sido modificado."}, status=status.HTTP_400_BAD_REQUEST)
                
                response = FileResponse(decrypted_file, as_attachment=True, filename=file.file_name)
                return response
            return Response({"error": "No se ha encontrado el archivo."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error al descargar el archivo: {e}")
            return Response({"error": "Error al descargar el archivo."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# La vista de eliminación de archivo se utiliza para eliminar un archivo de un grupo.    
@login_required
def delete_file_view(request, file_id):
    file = get_object_or_404(File, pk=file_id)
    group = file.group
    if group.owner != request.user:
        messages.error(request, "No tienes permiso para eliminar este archivo.")
        return redirect('group_detail', group_id=group.id)
    # Primero eliminamos el archivo físico del sistema de archivos
    file.file.delete()
    # Luego eliminamos el registro del archivo de la base de datos
    file.delete()
    messages.success(request, "Archivo eliminado exitosamente.")
    return redirect('group_detail', group_id=group.id)

class DeleteFileView(APIView):
    def delete(self, request, file_id):
        file = get_object_or_404(File, pk=file_id)
        group = file.group
        if group.owner != request.user:
            return Response({"error": "No tienes permiso para eliminar este archivo."}, status=status.HTTP_403_FORBIDDEN)
        file.file.delete()  # Elimina el archivo físico
        file.delete()  # Elimina el registro del archivo
        return Response({"message": "Archivo eliminado exitosamente."}, status=status.HTTP_200_OK)

# La vista de eliminación de grupo se utiliza para eliminar un grupo.
@login_required
def delete_group_view(request, group_id):
    group = get_object_or_404(Group, pk=group_id)
    if group.owner != request.user:
        messages.error(request, "No tienes permiso para eliminar este grupo.")
        return redirect('personal_page')
    elif group.group_name == f"{request.user.username}_personal_data":
        messages.error(request, "No puedes eliminar tu grupo personal.")
        return redirect('personal_page')
    elif group.files.exists():
        for file in group.files.all():
            if file.file_name == "":
                file.delete()
            if group.files.count() == 0:
                group.delete()
                messages.success(request, "Grupo eliminado correctamente.")
                return redirect('personal_page')
        print(group.files.exists())
        messages.error(request, "No puedes eliminar este grupo porque aún contiene ficheros. Elimina los ficheros primero.")
        return redirect('group_detail', group_id=group_id)
    else:
        group.delete()
        messages.success(request, "Grupo eliminado correctamente.")
        return redirect('personal_page')
    
# La vista de eliminación de grupo integrada con React se utiliza para eliminar un grupo.
class DeleteGroupView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, group_id):
        group = get_object_or_404(Group, pk=group_id)
        if group.owner != request.user:
            return Response({"error": "No tienes permiso para eliminar este grupo."}, status=status.HTTP_403_FORBIDDEN)
        elif group.group_name == f"{request.user.username}_personal_data":
            return Response({"error": "No puedes eliminar tu grupo personal."}, status=status.HTTP_403_FORBIDDEN)
        elif group.files.exists():
            return Response({"error": "No puedes eliminar este grupo porque aún contiene ficheros. Elimina los ficheros primero."}, status=status.HTTP_403_FORBIDDEN)
        else:
            group.delete()
            return Response({"message": "Grupo eliminado correctamente."}, status=status.HTTP_200_OK)
# La vista de eliminación de miembro de grupo se utiliza para eliminar un miembro de un grupo.
@login_required
def delete_member_view(request, group_id, member_id):
    group = get_object_or_404(Group, pk=group_id)
    group_member = get_object_or_404(GroupMember, pk=member_id)
    member = group_member.user
    if group.owner != request.user:
        messages.error(request, "No tienes permiso para eliminar miembros de este grupo.")
        return redirect('group_detail', group_id=group.id)
    try:
        for group_member in group.members.all():
            if group_member.user == member:
                group_member.delete()  # Eliminamos al miembro del grupo
        messages.success(request, "Miembro eliminado exitosamente.")
    except GroupMember.DoesNotExist:
        messages.error(request, "Este usuario no es miembro del grupo.")
    except Exception as e:
        messages.error(request, f"Error al eliminar miembro del grupo: {str(e)}")
    return redirect('group_detail', group_id=group.id)

class DeleteMemberView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, group_id, member_id):
        group = get_object_or_404(Group, pk=group_id)
        group_member = get_object_or_404(GroupMember, pk=member_id)
        if group.owner != request.user:
            return Response({"error": "No tienes permiso para eliminar miembros de este grupo."}, status=status.HTTP_403_FORBIDDEN)
        try:
            group_member.delete()
            return Response({"message": "Miembro eliminado exitosamente."}, status=status.HTTP_200_OK)
        except GroupMember.DoesNotExist:
            return Response({"error": "Este usuario no es miembro del grupo."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Error al eliminar miembro del grupo: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Serialización de los modelos: se utilizan para convertir los modelos en JSON y enviarlos a través de la API al frontend.
@method_decorator(auth_required, name='dispatch')
class UserViewSet(viewsets.ModelViewSet):
    queryset = AppUser.objects.all()
    serializer_class = UserSerializer

@method_decorator(auth_required, name='dispatch')
class FileViewSet(viewsets.ModelViewSet):
    queryset = File.objects.all()
    serializer_class = FileSerializer

@method_decorator(auth_required, name='dispatch')
class AccessRequestViewSet(viewsets.ModelViewSet):
    queryset = AccessRequest.objects.all()
    serializer_class = AccessRequestSerializer


class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.get(email=email)
        if not user:
            return Response({'error': 'No existe un usuario con ese email.'}, status=status.HTTP_404_NOT_FOUND)
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}"
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_url': reset_url,
            })
            send_mail(
                'Password Reset Request',
                '',
                settings.EMAIL_HOST_USER,
                [user.email],
                html_message=message
            )
        return Response({'message': 'If a user with that email exists, a password reset link has been sent.'}, status=status.HTTP_200_OK)

class PasswordResetView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            password = request.data.get('password')
            password_confirm = request.data.get('confirmPassword')
            # Comparamos la contraseña mandada con la actual, que no deben coincidir y en caso de hacerlo, devolvemos un error. Como la contraseña se guarda en un hash, no podemos compararla directamente, por lo que usamos la función check_password
            if check_password(password, user.password):
                return Response({'error': 'La nueva contraseña no puede ser igual a la anterior.'}, status=status.HTTP_400_BAD_REQUEST)
            if password and password == password_confirm:
                user.set_password(password)
                # Si el usuario está inactivo, lo activamos (por si se ha desactivado por fallos en el login)
                if user.is_active == False:
                    user.is_active = True
                user.save()
                return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)


"""

class LoginView(APIView):
    permission_classes = [AllowAny] # Permite a los usuarios no autenticados acceder a esta vista
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                username = serializer.validated_data['username']
                password = serializer.validated_data['password']
                print("Username:", username)  # Añade detalles de depuración
                print("Password:", password)  # Añade detalles de depuración
                user = authenticate(username=username, password=password)
                # En peticiones posteriores, realizamos la autenticación con JWTAutentication
                # user = JWTAuthentication().authenticate(request) # Devuelve una tupla con el usuario y el token
                if user is not None:
                    print("User authenticated:", user)  # Añade detalles de depuración
                    login(request, user)  # Inicia sesión en la aplicación
                    # Generamos un token de refresco, que se utiliza para obtener un nuevo token de acceso si el token de acceso ha expirado o si el usuario sigue autenticado
                    refresh_token = RefreshToken.for_user(user) 
                    # Obtiene el token de acceso actual
                    access_token = refresh_token.access_token
                    response = Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
                    # Response se distingue de response en que Response es una clase que se utiliza para devolver una respuesta en Django REST framework.
                    # Establecemos un tiempo de expiración de cookie de 5 minutos para el token de autenticación
                    response = Response({'message': 'Login successful'}, status=status.HTTP_200_OK)

                    if 'authtoken' in request.COOKIES:
                        response.delete_cookie('authtoken')
                    if 'refreshtoken' in request.COOKIES:
                        response.delete_cookie('refreshtoken')
                    response.set_cookie(
                        key='refreshtoken',
                        value=str(refresh_token),
                        httponly=True,
                        # secure=True,  # Solo si usas HTTPS
                        samesite='Lax', # O 'Strict' si quieres que no se envíe en peticiones de terceros
                        max_age=60*60,  # 1 hora
                    )
                    response.set_cookie(
                        key='authtoken', 
                        value=str(access_token),
                        httponly=True,
                        samesite='Lax',
                        max_age=60*5,
                    )
                    # Generamos un token CSRF y lo añadimos a la respuesta en la cabecera X-CSRFToken
                    response['X-CSRFToken'] = get_token(request)
                    # Añadimos el token de autenticación a la respuesta en la cabecera Authorization
                    response['Authorization'] = f'Bearer {access_token}'
                    return response
                    # Si el usuario es autenticado, se genera un token de autenticación y se devuelve en la respuesta al frontend. Tiene que redirigir a la página de inicio.
                print("Authentication failed")  # Añade detalles de depuración
                user = User.objects.get(username=username)
                if check_password(password, user.password):
                    print("Password correct, there is an error in the authentication process")  # Añade detalles de depuración
                else:
                    print("Password incorrect")
                return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
            print("Serializer invalid:", serializer.errors)  # Añade detalles de depuración
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(traceback.format_exc())
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

"""