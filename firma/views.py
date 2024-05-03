import logging
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework.permissions import AllowAny
from .models import Product
from .serializers import ProductSerializer
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from .tokens import account_activation_token


User = get_user_model()


@csrf_exempt
def product_list(request):
    if request.method == "GET":
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return JsonResponse(serializer.data, safe=False)
    elif request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = ProductSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)

@csrf_exempt
def product_detail(request, pk):
    try:
        product = Product.objects.get(pk=pk)
    except Product.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = ProductSerializer(product)
        return JsonResponse(serializer.data)

    elif request.method == 'PUT':
        data = JSONParser().parse(request)
        serializer = ProductSerializer(product, data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data)
        return JsonResponse(serializer.errors, status=400)

    elif request.method == 'DELETE':
        product.delete()
        return HttpResponse(status=204)


class LoginView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = User.objects.filter(Q(username=username) | Q(email=username)).first()
        if user is not None:
            user = authenticate(username=username, password=password)
            if user.email_confirmed:
                token, created = Token.objects.get_or_create(user=user)
                return JsonResponse({'token': token.key, 'email_confirmed': user.email_confirmed})
            else:
                return JsonResponse({'errors': 'Please confirm your email address.'}, status=401)

class RegistrationView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        username = request.data.get('username')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Nazwa użytkownika jest zajęta'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email jest już w użyciu'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(email=email, password=password, username=username, email_confirmed=False)
        token, _ = Token.objects.get_or_create(user=user)
        self.send_activation_email(user, request)
        return Response({'token': token.key, 'email_confirmed': user.email_confirmed}, status=status.HTTP_201_CREATED)

    def send_activation_email(self, user, request):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = f"http://localhost:3000/activate/{uid}/{token}"
        subject = 'Aktywuj swoje konto'
        message = f'Witaj {user.username},\nUźyj tego linku aby potwierdzić swój adres e-mail i aktywować konto {activation_link}'
        from_email = "komputer290123@gmail.com"
        recipient_list = [user.email]
        try:
            send_mail(subject, message, from_email, recipient_list)
        except Exception as e:
            print(e)


def activate_account(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        print("Encoded UID:", uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is None:
        return HttpResponse('Activation link is invalid!', status=400)
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.email_confirmed = True
        user.save()
        return HttpResponse('Account activated successfully')
    else:
        return HttpResponse('Activation link is invalid!', status=400)