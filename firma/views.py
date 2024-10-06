from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.sites import requests
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.permissions import AllowAny
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.utils import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status, viewsets, generics, filters
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import account_activation_token
from .serializers import ProductSerializer
from .models import Product, Order, Cart
from django_filters import CharFilter, FilterSet, RangeFilter

User = get_user_model()


class ProductDetailView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]


class ProductFilter(FilterSet):
    producer = CharFilter(field_name='producer', method='filter_by_producer')
    price = RangeFilter()
    class Meta:
        model = Product
        fields = ['category', 'producer', 'price']

    def filter_by_producer(self, queryset, name, value):
        producers = value.split(',')
        return queryset.filter(producer__in=producers)


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ProductFilter


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
        return JsonResponse({'errors': 'Invalid credentials.'}, status=400)


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
        message = f'Witaj {user.username},\n Uźyj tego linku aby potwierdzić swój adres e-mail i aktywować konto {activation_link}'
        from_email = "komputer290123@gmail.com"
        recipient_list = [user.email]
        try:
            send_mail(subject, message, from_email, recipient_list, token)
        except Exception as e:
            print(e)


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and account_activation_token.check_token(user, token):
        user.is_active = True
        user.email_confirmed = True
        user.save()
        return HttpResponse('Account activated successfully', request)
    else:
        return JsonResponse({'error': 'Invalid token', 'user': user.username}, status=400)


def create_order(request):
    data = request.data
    try:
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        address = data.get('address')
        zip_code = data.get('zipCode')
        city_name = data.get('city')
        phone = data.get('phone')
        email = data.get('email')
        delivery=data.get('deliveryType')
        order = Order.objects.create(
            first_name=first_name,
            last_name=last_name,
            address=address,
            city_code=zip_code,
            city_name=city_name,
            email=email,
            phone=phone,
            delivery=delivery
        )
        order.generate_secret()  # Generate the order secret for tracking
        order.save()
        return Response({'message': 'Order created successfully!'}, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)