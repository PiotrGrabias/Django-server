from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'products', views.ProductViewSet)
router.register(r'carts', views.CartViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/login/', views.LoginView.as_view(), name='login'),
    path('api/register/', views.RegistrationView.as_view(), name='register'),
    path('api/activate/<uidb64>/<token>/', views.ActivateAccountView.as_view(), name='activate'),
    path('api/product/<int:pk>/', views.ProductDetailView.as_view(), name='product-detail'),
    path('api/products/', views.FilterByCategoryorProducer.as_view(), name='filtered-products'),
]