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
        user = self.model(email=email, **extra_fields)  # Create a user object with email and extra fields
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
    description = models.CharField(max_length=200, default='Opis')
    image_path = models.CharField(max_length=200)
    amount = models.IntegerField()
    date_added = models.DateTimeField("date published", default=timezone.now)
    
    def new(self):
        self.date_added = dateformat.format(timezone.now(), 'Y-m-d')
        return self.date_added >= timezone.now()

    def added_last_week(self):
        seven_days_ago = self.date_added - datetime.timedelta(days=7)
        return seven_days_ago >= 7

    def __str__(self):
        return self.product_name


class Cart(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    products = models.ManyToManyField(Product, through='CartItem')

    def __str__(self):
        return self.products


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return self.cart, self.product, self.quantity





