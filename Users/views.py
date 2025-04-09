from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from Users.serializers import UserSerializer
from Users.models import User
import jwt, datetime

class RegisterView(APIView):
    def post(self, request):
        serialzer = UserSerializer(data=request.data)
        serialzer.is_valid(raise_exception=True)
        serialzer.save()
        return Response(serialzer.data)
    
class LoginView(APIView):
    def post(self, request):
        email=request.data['email']
        password=request.data['password']

        user=User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed("User Not Found")
        
        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect Password")
        
        payload ={
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow()
        }   

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        jwtresponse = Response()
        jwtresponse.set_cookie(key='jwt', value=token, httponly=True) # httponly =True -> We don't want frontend to handle token
        jwtresponse.data = { 
                'jwt': token
            }

        return jwtresponse


class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
class LogoutView(APIView):
    def post(self, request):
        response=Response()
        response.delete_cookie('jwt')
        response.data = {
            "message":"Logout successfully"
        }
        return response