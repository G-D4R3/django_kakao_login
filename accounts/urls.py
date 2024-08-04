from django.urls import path, include
from rest_framework.routers import SimpleRouter

from accounts.views import KaKaoLoginViewSet

app_name = 'accounts'

router = SimpleRouter()
router.register('kakao', KaKaoLoginViewSet, basename='kakao')

urlpatterns = [
    path('', include((router.urls, 'accounts')))
]