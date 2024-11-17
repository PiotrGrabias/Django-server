from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import CreateProductView, UpdateProductView, AllOrders, ContactEmail

router = DefaultRouter()
router.register(r'products', views.ProductViewSet)

urlpatterns = [
    path('api/create/', CreateProductView.as_view(), name='create-product'),
    path('api/', include(router.urls)),
    path('api/submit-order', views.CreateOrder.as_view(), name="order"),
    path('api/user-orders', views.GetOrders.as_view(), name="user-orders"),
    path('api/login/', views.LoginView.as_view(), name='login'),
    path('api/register/', views.RegistrationView.as_view(), name='register'),
    path('api/activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('api/product/<int:pk>/', views.ProductDetailView.as_view(), name='product-detail'),
    path('api/products/<int:pk>/decrement/', views.DecrementQuantity.as_view(), name='decrement_product_quantity'),
    path('api/product/<int:product_id>/update/', UpdateProductView.as_view(), name='update_product'),
    path('api/all-orders/', AllOrders.as_view(), name='all_orders'),
    path('api/contact/', ContactEmail.as_view(), name='contact-email'),
]
