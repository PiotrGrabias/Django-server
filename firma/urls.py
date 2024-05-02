from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views

urlpatterns = [
    path("products/", views.product_list),
    path("register/", views.RegistrationView.as_view()),
    path("login/", views.LoginView.as_view()),
    path("products/<int:pk>/", views.product_detail),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
