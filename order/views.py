from django.core.serializers import serialize
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response

from card.models import Cart
from order.models import Order, OrderItem
from order.serializers import OrderSerializer


class Response:
    pass


class OrderCreatedView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            cart = Cart.objects.get(user=request.user)
        except Cart.DoesNotExist:
            return Response({"error": "Savat topilmadi"}, status=400)

        if not cart.items.exists():
            return Response({"error": "Savat bo‘sh"}, status=400)

        order = Order.objects.create(user=request.user)
        total = 0

        for item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=item.product,
                price=item.product.price,
                quantity=item.quantity
            )
            total += item.product.price * item.quantity

        order.total_price = total
        order.save()

        cart.items.all().delete()

        return Response(
            {
                "detail": "Buyurtma yaratildi",
                "order_id": order.id
            },
            status=201
        )

class OrderListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        orders = Order.objects.filter(user=request.user)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class OrderDatailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        order=Order.objects.get(id=id, user=request.user)
        serializer=OrderSerializer(order)
        return Response(serializer.data)

    from rest_framework.permissions import IsAdminUser

class OrderStatusUpdateView(APIView):
    permission_classes = [IsAdminUser]

    def patch(self, request, pk):
        status_value=request.data.get("status")
        order=Order.objects.get(id=id)
        order.status=status_value
        order.save()
        return Response({"detail": "Status yangilandi"})


class OrderCancelView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self,request,id):
        order=Order.objects.get(id=id, user=request.user)
        order.status="cancelled"
        order.save()
        return Response({"detail": "Buyurtma bekor qilindi"})