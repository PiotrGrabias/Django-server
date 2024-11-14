import random

from django.conf import settings
from django.db import models
from django.contrib.auth.models import UserManager, AbstractUser
import datetime
from django.utils import timezone, dateformat


class CustomUserManager(UserManager):
    use_in_migrations = True

    def _create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    objects = CustomUserManager()
    email = models.EmailField(unique=True)
    email_confirmed = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


class Product(models.Model):
    product_name = models.CharField(max_length=200)
    price = models.FloatField()
    producer = models.CharField(max_length=200, default="GOODRAM")
    category = models.CharField(max_length=200, default="ram")
    description = models.CharField(max_length=10000, default='Opis')
    image_path = models.CharField(max_length=200)
    amount = models.IntegerField()
    date_added = models.DateTimeField("date published", default=timezone.now)
    sold_amount = models.IntegerField(default=0)

    @property
    def added_last_week(self):
        now = timezone.now()
        seven_days_ago = now - datetime.timedelta(days=7)
        return self.date_added >= seven_days_ago

    def __str__(self):
        return self.product_name


class Order(models.Model):
    secret = models.CharField(max_length=1000, default="", blank=True)
    first_name = models.CharField(max_length=100, default="")
    last_name = models.CharField(max_length=100, default="")
    address = models.CharField(max_length=255, default="")
    city_code = models.CharField(max_length=100, default="")
    city_name = models.CharField(max_length=100, default="")
    email = models.EmailField(max_length=255)
    phone = models.CharField(max_length=20, default="")
    date_created = models.DateTimeField(auto_now_add=True)
    price = models.FloatField(default=0)
    delivery = models.CharField(max_length=255, default="")
    products = models.JSONField(default=dict)
    image = models.JSONField(default=dict)


    def generate_secret(self):
        self.secret = str(random.randint(10000, 99999))







