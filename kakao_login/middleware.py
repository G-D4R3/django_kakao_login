from django.core.handlers.wsgi import WSGIRequest
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from rest_framework import status, HTTP_HEADER_ENCODING
from django.utils.translation import gettext_lazy as _
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPE_BYTES, AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import SlidingToken

from accounts.models import User

class CustomAuthenticationMiddleware(MiddlewareMixin):
    www_authenticate_realm = 'api'
    media_type = 'application/json'

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), validated_token

    def authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get(api_settings.AUTH_HEADER_NAME)

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)

        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                _('Authorization header must contain two space-delimited values'),
                code='bad_authorization_header',
            )

        return parts[1]

    def get_validated_token(self, raw_token):
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """
        messages = []
        for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
            try:
                return AuthToken(raw_token)
            except TokenError as e:
                messages.append({'token_class': AuthToken.__name__,
                                 'token_type': AuthToken.token_type,
                                 'message': e.args[0]})

        raise InvalidToken({
            'detail': _('Given token not valid for any token type'),
            'messages': messages,
        })

    def get_user(self, validated_token):
        """
        Attempts to find and return a user using the given validated token.
        """
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise InvalidToken(_('Token contained no recognizable user identification'))

        try:
            user = User.objects.get(**{api_settings.USER_ID_FIELD: user_id})
        except User.DoesNotExist:
            raise AuthenticationFailed(_('User not found'), code='user_not_found')

        if not user.is_active:
            raise AuthenticationFailed(_('User is inactive'), code='user_inactive')

        return user

    def set_jwt_cookie(self, request: WSGIRequest, response: Response):
        if request.user.is_authenticated:
            jwt = SlidingToken.for_user(request.user)
            origin = request.headers.get('origin')
            is_local = False if origin is None or 'localhost' not in origin else True
            domain = None if is_local else '.zps.kr'
            response.set_cookie(
                'jwt',
                str(jwt),
                max_age=3600*24*3,
                domain=domain,
                secure=(not is_local),
                httponly=True,
                samesite=False,
            )
        elif request.COOKIES.get('jwt', None) is not None:
            response.set_cookie(
                'jwt', max_age=0, domain='.zps.kr', secure=True,
                expires='Thu, 01 Jan 1970 00:00:00 GMT', samesite=False,
            )

        return response

    def process_request(self, request):
        if request.user.is_authenticated:
            return
        try:
            user, validated_token = self.authenticate(request)
            request.user = user
        except:
            return
    def process_response(self, request, response):
        # if request.path == reverse('accounts:accounts:users-logout'):
        #     response = self.set_jwt_cookie(request, response)
        #     # try:
        #     #     if response.data['code'] and response.data['code'].code == 'token_not_valid':
        #     #         response.status_code = 200
        #     #         response = self.set_jwt_cookie(request, response)
        #     # except Exception as e:
        #     #     raise e
        return self.set_jwt_cookie(request, response)