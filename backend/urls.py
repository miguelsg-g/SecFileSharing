"""
URL configuration for SecFileSharingApp project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
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
from . import views
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
# router es un objeto que nos permite registrar las vistas de la aplicación
router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)
router.register(r'files', views.FileViewSet)
router.register(r'access_requests', views.AccessRequestViewSet)

urlpatterns = [
    # Incluimos las vistas de la aplicación
    path('', views.index, name='index'),
    path('admin/', admin.site.urls, name='admin'),
    path('admin/logout/', views.logout_view, name='admin_logout'),
    path('favicon.ico', views.favicon, name='favicon'),
    path('register/', views.register_view, name='sign_up'),   
    path('login/', views.login_view, name='log_in'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('share_file/', views.upload_file_view, name='share_file'),
    path('access_request/', views.access_request_view, name='access_request'),
    path('group/', views.group_view, name='group'),
    path('create_group/', views.create_group_view, name='create_group'),
    path('accept_access_request/<int:access_request_id>/', views.accept_access_request_view, name='accept_access_request'),
    path('reject_access_request/<int:access_request_id>/', views.reject_access_request_view, name='reject_access_request'),
    path('group_detail/<int:group_id>/', views.group_detail_view, name='group_detail'),
    path('file_detail/<int:file_id>/', views.file_detail_view, name='file_detail'),
    path('download_file/<int:file_id>/', views.download_file_view, name='download_file'),
    path('delete_file/<int:file_id>/', views.delete_file_view, name='delete_file'),
    path('verificate_email/<uidb64>/<token>/', views.verify_email_view, name='verificate_email'),
    path('verification_request/', views.verification_request_view, name='verification_request'),
    path('personal/', views.personal_page_view, name='personal_page'),  # Página personal del usuario
    path('upload_file/', views.upload_file_view, name='upload_file'),  # Subida de archivos
    path('upload_file/<int:group_id>/', views.upload_file_view, name='upload_file_with_group'),  # Subida de archivos a un grupo específico
    path('group/<int:group_id>/files/', views.group_detail_view, name='group_detail'),  # Listado de archivos de un grupo
    path('group/<int:group_id>/add_members/', views.add_group_members_view, name='add_group_members'),  # Añadir miembros a un grupo
    path('groups/request_access/<int:group_id>/', views.request_access_view, name='request_access'),
    path('groups/manage_request/<int:request_id>/<str:action>/', views.manage_access_requests_view, name='manage_access_request'),
    path('files/delete/<int:file_id>/', views.delete_file_view, name='delete_file'),
    path('delete_group/<int:group_id>/', views.delete_group_view, name='delete_group'),
    path('delete_member/<int:group_id>/<int:member_id>/', views.delete_member_view, name='delete_member'),
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')), # URLs de autenticación de la API para el navegador
    path('api/register/', views.RegisterView.as_view(), name='register'),
    path('api/verify-email/<uidb64>/<token>/', views.VerifyEmailView.as_view(), name='verify_email'),
    # path('api/login/', views.LoginView.as_view(), name='login'),
    path('api/logout/', views.LogoutView.as_view(), name='logout'),
    path('api/dashboard/', views.DashboardView.as_view(), name='rest_dashboard'),
    path('api/token-auth/', TokenObtainPairView.as_view(), name='token_obtain_pair_auth'),
    path('api/token/', views.JWTLoginView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='refresh_token'),
    path('api/personal_page/', views.PersonalPageView.as_view(), name='personal_page'),
    path('api/group/<int:group_id>/', views.GroupDetailView.as_view(), name='group'),
    path('api/create_group/', views.CreateGroupView.as_view(), name='create-group'),
    path('api/upload_file/', views.UploadFileView.as_view(), name='upload-file'),
    path('api/download_file/<int:file_id>/', views.DownloadFileView.as_view(), name='download-file'),
    path('api/delete_file/<int:file_id>/', views.DeleteFileView.as_view(), name='delete-file'),
    path('api/delete_group/<int:group_id>/', views.DeleteGroupView.as_view(), name='delete-group'),
    path('api/delete_member/<int:group_id>/<int:member_id>/', views.DeleteMemberView.as_view(), name='delete-member'),
    path('api/group/<int:group_id>/add_members/', views.AddGroupMembersView.as_view(), name='add-members'),
    path('api/group/<int:group_id>/users/', views.UserListView.as_view(), name='user_list'),
    path('api/request_access/<int:group_id>/', views.AccessRequestView.as_view(), name='request_access'),
    path('api/handle_access_request/<int:request_id>/<str:action>/', views.HandleAccessRequestView.as_view(), name='handle_access_request'),
    path('api/group/<int:group_id>/access_requests/', views.AccessRequestsListView.as_view(), name='access_requests'),
    path('api/password-reset-request/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('api/reset_password/<uidb64>/<token>/', views.PasswordResetView.as_view(), name='password_reset'), # uidb64 es un identificador de usuario codificado en base64
    path('api/csrf_cookie/', views.csrf_token_view, name='csrf_token'),
]