import logging
from django.middleware.csrf import get_token
from django.utils.deprecation import MiddlewareMixin # Esto es necesario para que el middleware funcione en Django 1.10 o superior

logger = logging.getLogger(__name__)

class EnsureCsrfCookieMiddleware(MiddlewareMixin):
    def process_request(self, request):
        get_token(request)
        return None
    
    def process_response(self, request, response):
        response['X-CSRFToken'] = get_token(request)
        return response

"""
class TokenAuthMiddleware(MiddlewareMixin):
    # esta función se ejecuta en cada petición que llega al servidor si el middleware está habilitado
    def process_request(self, request):
        auth_token = request.COOKIES.get('authtoken')
        if auth_token:
            try:
                token = Token.objects.get(key=auth_token)
                request.user = token.user # Attach the user object to the request
                request.auth = token # Attach the token object to the requestº
            except Token.DoesNotExist:
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            request.user = User()
            request.auth = None
        return None
"""

