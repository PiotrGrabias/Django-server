from rest_framework import serializers
from .models import Product, CustomUser, Order
from django.contrib.auth.models import User


class ProductSerializer(serializers.ModelSerializer):
    added_last_week = serializers.BooleanField(read_only=True)

    class Meta:
        model = Product
        fields = ['product_name', 'price', 'producer', 'category', 'description', 'image_path', 'amount', 'date_added', 'added_last_week', 'sold_amount']


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data['email'],
            username=validated_data['username']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
