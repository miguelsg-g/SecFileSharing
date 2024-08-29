import logging
from rest_framework.response import Response
from rest_framework import status
from functools import wraps
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

logger = logging.getLogger(__name__)

def auth_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        jwt_authenticator = JWTAuthentication()
        auth_header = request.headers.get('Authorization', None)     

        if not auth_header:
            logger.warning("DECORADOR PROPIO: Authentication required but no token found in headers")
            # Indicar error 401 para que el cliente sepa que necesita autenticarse o refrescar el token
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Verifica el formato del token (debe ser "Bearer <token>")
            if not auth_header.startswith('Bearer '):
                logger.warning("Token should start with 'Bearer '")
                return Response({'error': 'Invalid token format'}, status=status.HTTP_401_UNAUTHORIZED)
            
            token = auth_header.split(' ')[1]
            validated_token = jwt_authenticator.get_validated_token(token)
            user = jwt_authenticator.get_user(validated_token)
            request.user = user
            request.auth = validated_token

            logger.info(f"Authenticated user: {request.user.username}")
            return view_func(request, *args, **kwargs)
        except (TokenError) as e:
            logger.error(f"Invalid token: {e}")
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except (InvalidToken) as e:
            logger.error("Expired token")
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return Response({'error': 'Authentication error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return _wrapped_view