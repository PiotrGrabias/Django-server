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


class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]


from django_filters import FilterSet, RangeFilter, CharFilter


class ProductFilter(FilterSet):
    producer = CharFilter(field_name='producer', method='filter_by_producer')
    price = RangeFilter()

    class Meta:
        model = Product
        fields = ['category', 'producer', 'price']

    def filter_by_producer(self, queryset, name, value):
        producers = value.split(',')
        return queryset.filter(producer__in=producers)

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)

        price_min = self.data.get('price_min', None)
        price_max = self.data.get('price_max', None)

        if price_min:
            queryset = queryset.filter(price__gte=price_min)
        if price_max:
            queryset = queryset.filter(price__lte=price_max)

        return queryset


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
            product.sold_amount += quantity_to_decrement
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
                return JsonResponse({'token': token.key, 'email_confirmed': user.email_confirmed,
                                     'is_superuser': user.is_superuser})
            elif user.is_superuser:
                token, created = Token.objects.get_or_create(user=user)
                return JsonResponse({'token': token.key, 'email_confirmed': user.email_confirmed,
                                     'is_superuser': user.is_superuser})
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
            # Extract order data
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

            # Create the order
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

            # Send confirmation email
            self.order_confirmation(order, email)
            return Response({"message": "Order created successfully!"}, status=201)

        except Exception as e:
            print(e)
            return Response({"error": "Order creation failed."}, status=400)

    def order_confirmation(self, order, recipient_email):
        subject = "Potwierdzenie zamówienia"
        message = (
            f"Dzień dobry {order.first_name} {order.last_name},\n\n"
            f"Dziękujemy za złożenie zamówienia w naszym sklepie!\n\n"
            f"**Szczegóły zamówienia:**\n"
            f"Adres dostawy: {order.address}, {order.city_code} {order.city_name}\n"
            f"Telefon kontaktowy: {order.phone}\n"
            f"Metoda dostawy: {order.delivery}\n"
            f"Łączna kwota: {order.price} PLN\n\n"
            f"Produkty w zamówieniu:\n"
        )

        # Add items to the message
        for prod_id, details in order.products.items():
            prod_name = details['prodName']
            amount = details['amount']
            message += f"- {prod_name} (ilość: {amount})\n"

        # Conclude the email
        message += (
            "\nTwoje zamówienie jest obecnie przetwarzane. "
            "W razie pytań prosimy o kontakt pod adresem: komputer290123@gmail.com.\n\n"
            "Z poważaniem,\nZespół Pc-parts"
        )

        # Send the email
        try:
            send_mail(subject, message, "komputer290123@gmail.com", [recipient_email])
        except Exception as e:
            print(f"Error sending email: {e}")

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


class AllOrders(APIView):
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            orders = Order.objects.all()
            serializer = OrderSerializer(orders, many=True)

            # Wrap the data in an 'attributes' key
            orders_data = [
                {"attributes": order} for order in serializer.data
            ]

            return Response(orders_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class OrderFilter(FilterSet):
    email = CharFilter(field_name='email', lookup_expr='icontains')
    status = CharFilter(field_name='status', lookup_expr='iexact')

    class Meta:
        model = Order
        fields = ['email', 'status']


class GetOrders(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        try:
            orders = Order.objects.all()
            filterset = OrderFilter(request.query_params, queryset=orders)
            if filterset.is_valid():
                orders = filterset.qs

            orders = orders.order_by('-date_created')

            serializer = OrderSerializer(orders, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CreateProductView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        data = request.data

        product_name = data.get('name')
        price = data.get('price')
        producer = data.get('producer')
        category = data.get('category')
        description = data.get('description')
        image_path = data.get('image_path')
        amount = data.get('amount')

        if not all([product_name, price, producer, category, amount]):
            return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            product = Product.objects.create(
                product_name=product_name,
                price=price,
                producer=producer,
                category=category,
                description=description,
                image_path=image_path,
                amount=amount
            )

            return Response({
                'message': 'Product created successfully!',
                'product': {
                    'id': product.id,
                    'product_name': product.product_name,
                    'price': product.price,
                    'producer': product.producer,
                    'category': product.category,
                    'description': product.description,
                    'image_path': product.image_path,
                    'amount': product.amount
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Handle unexpected errors
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UpdateProductView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def put(self, request, product_id):
        data = request.data

        # Retrieve the product to update
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Extract and validate fields from the request
        product_name = data.get('product_name')
        price = data.get('price')
        producer = data.get('producer')
        category = data.get('category')
        description = data.get('description')
        image_path = data.get('image_path')
        amount = data.get('amount')

        if not all([product_name, price, producer, category, amount]):
            return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        # Update the product fields
        product.product_name = product_name
        product.price = price
        product.producer = producer
        product.category = category
        product.description = description
        product.image_path = image_path
        product.amount = amount

        # Save changes to the database
        product.save()

        # Return a success response with updated product data
        return Response({
            'message': 'Product updated successfully!',
            'product': {
                'id': product.id,
                'product_name': product.product_name,
                'price': product.price,
                'producer': product.producer,
                'category': product.category,
                'description': product.description,
                'image_path': product.image_path,
                'amount': product.amount
            }
        }, status=status.HTTP_200_OK)