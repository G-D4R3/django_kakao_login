from django.urls import path, include
from rest_framework.routers import SimpleRouter

from accounts.views import KaKaoLoginViewSet, UserViewSet

app_name = 'accounts'

router = SimpleRouter()
router.register('kakao', KaKaoLoginViewSet, basename='kakao')
router.register('users', UserViewSet, basename='users')

urlpatterns = [
    path('', include((router.urls, 'accounts')))
]