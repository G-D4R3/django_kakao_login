from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None and response.get('data') is not None:
        if response.data.get('code') is None and getattr(exc, 'default_code', None) is not None:
            response.data['code'] = exc.default_code
    return response
