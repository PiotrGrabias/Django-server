import logging
from django.contrib.auth import authenticate, get_user_model
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


class RegistrationView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        User.is_active = False
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(email=email, password=password, username=username)
        token, _ = Token.objects.get_or_create(user=user)
        self.send_activation_email(user, request)
        return Response({'token': token.key}, status=status.HTTP_201_CREATED)

    def send_activation_email(self, user, request):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = f"http://localhost:3000/activate/{uid}/{token}"
        subject = 'Aktywuj swoje konto'
        message = f'Witaj {user.username},\nUźyj tego linku aby potwierdzić swój adres e-mail i aktywować konto {activation_link}'
        from_email = "komputer290123@gmail.com"
        recipient_list = ['komputer2901@wp.pl']
        try:
            send_mail(subject, message, from_email, recipient_list)
        except Exception as e:
            print(e)

logger = logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        login = request.data.get('login')
        password = request.data.get('password')

        logger.debug(f"Attempting login with: login={login}, password={password}")

        user = User.objects.filter(Q(username=login) | Q(email=login)).first()
        if not user:
            logger.error("User not found or incorrect login method.")
            return JsonResponse({'errors': {'error': 'Invalid Credentials'}}, status=401)

        user = authenticate(username=user.username, password=password)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            logger.debug(f"Token created: {token.key}")
            return JsonResponse({'token': token.key})
        else:
            logger.error("Authentication failed - check username and password.")
            return JsonResponse({'errors': {'error': 'Invalid Credentials'}}, status=401)


def activate_account(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        print("Encoded UID:", uid)


    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is None:
        logger.error('User not found')
        return HttpResponse('Activation link is invalid!', status=400)

    logger.info(f'User: {user.username}, Token: {token}')

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Account activated successfully')
    else:
        logger.error('Invalid token')
        return HttpResponse('Activation link is invalid!', status=400)