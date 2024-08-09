import datetime
import random

import requests
from django.contrib.auth import logout
from django.shortcuts import redirect
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import SlidingToken

from accounts.models import User
from kakao_login.settings import KAKAO_REST_API_KEY, KAKAO_CLIENT_SECRET

KAKAO_TOKEN_API = "https://kauth.kakao.com/oauth/token"
KAKAO_USER_API = "https://kapi.kakao.com/v2/user/me"


class UserViewSet(viewsets.GenericViewSet):

    @action(methods=['POST'], detail=False, permission_classes=[IsAuthenticated])
    def logout(self, request: Request):
        logout(request)
        return Response()

    @action(detail=False, methods=['GET'])
    def user(self, request):

        user = request.user
        return Response(dict(email=user.email))


class KaKaoLoginViewSet(viewsets.GenericViewSet):
    @action(detail=False, methods=['GET'])
    def callback(self, request: Request):
        code = request.GET["code"]

        if not code:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # kakao에 access token 발급 요청
        data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_REST_API_KEY,
            "redirect_uri": "http://127.0.0.1:8000/api/accounts/kakao/callback/",
            "code": code,
            "client_secret": KAKAO_CLIENT_SECRET
        }
        headers = {"Content-type": "application/x-www-form-urlencoded;charset=utf-8"}
        token = requests.post(KAKAO_TOKEN_API, data=data, headers=headers).json()  # 받은 코드로 구글에 access token 요청하기
        access_token = token['access_token']  # 받은 access token
        if not access_token:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # kakao에 user info 요청
        headers = {"Authorization": f"Bearer ${access_token}"}
        user_infomation = requests.get(KAKAO_USER_API, headers=headers).json()  # 받은 access token 으로 user 정보 요청

        data = {'access_token': access_token, 'code': code}
        kakao_account = user_infomation.get('kakao_account')
        email = kakao_account.get('email')

        # 1. 유저가 이미 디비에 있는지 확인하기
        try:
            user = User.objects.get(email=email)

            token = token_serializer(user)

            return Response(dict(token=token))

        except User.DoesNotExist:
            # 2. 없으면 회원가입하기

            timestamp = int(datetime.datetime.now().timestamp())
            password = str(random.randint(0, timestamp))
            data = {
                'email': email,
                'password': password
                # 비밀번호는 없지만 validation 을 통과하기 위해서 임시로 사용
                # 비밀번호를 입력해서 로그인하는 부분은 없으므로 안전함
            }
            user = User.objects.create_user(email, password)  # todo: Profile은 나중에 create

            # 2-1. 회원가입 하고 토큰 만들어서 쿠키에 저장하기
            try:
                user = User.objects.get(email=email)
                token = token_serializer(user)
                return Response(dict(token=token))
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST)


def token_serializer(user):
    jwt_token = SlidingToken.for_user(user)
    rtn = dict(
        access=str(jwt_token),
        refresh=str(jwt_token)
    )
    return rtn
