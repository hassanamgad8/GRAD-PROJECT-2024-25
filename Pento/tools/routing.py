from django.urls import path
from .consumers import ScanNotificationConsumer

websocket_urlpatterns = [
    path('ws/notifications/', ScanNotificationConsumer.as_asgi()),
]
