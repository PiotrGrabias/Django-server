from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

router = routers.DefaultRouter()
urlpatterns = router.urls

urlpatterns += [
    path("jF8r$kL1pWz3Q@h9N7xG2kD!vA6YtO*5bTzLm0s/", admin.site.urls),
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),
    path("", include("firma.urls"))
]