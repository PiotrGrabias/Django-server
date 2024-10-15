from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status, viewsets, generics
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import account_activation_token
from .serializers import ProductSerializer, OrderSerializer
from .models import Product, Order
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


class DecrementQuantity(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    def patch(self, request, pk):
        print(request.data)
        try:
            product = Product.objects.get(pk=pk)
            quantity_to_decrement = request.data.get('quantity', 1)

            if quantity_to_decrement > product.amount:
                return Response({'error': 'Not enough stock available.'}, status=status.HTTP_400_BAD_REQUEST)

            product.amount -= quantity_to_decrement
            product.save()
            return Response({'message': 'Quantity updated successfully.'}, status=status.HTTP_200_OK)

        except Product.DoesNotExist:
            return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)



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
            print(user)
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


class CreateOrder(APIView):
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        print(data)
        try:
            first_name = data.get('firstName')
            last_name = data.get('lastName')
            address = data.get('address')
            zip_code = data.get('zipCode')
            city_name = data.get('city')
            phone = data.get('phone')
            email = data.get('email')
            delivery_type = data.get('deliveryType')
            price = data.get('price')
            items = data.get('items')
            order = Order.objects.create(
                first_name=first_name,
                last_name=last_name,
                address=address,
                city_code=zip_code,
                city_name=city_name,
                email=email,
                phone=phone,
                delivery=delivery_type,
                price=price,
                products={item['id']: {'prodName': item['prodName'], 'amount': item['amount']} for item in items},
                image={item['id']: item['image'] for item in items}
            )
            order.generate_secret()
            order.save()

            return Response({'message': 'Order created successfully!'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        try:
            user_orders = Order.objects.filter(email=request.user.email)
            serializer = OrderSerializer(user_orders, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GetOrders(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            username = request.query_params.get('userName')
            print(username)
            user_orders = Order.objects.filter(email=username)
            serializer = OrderSerializer(user_orders, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            print("Error:", e)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)