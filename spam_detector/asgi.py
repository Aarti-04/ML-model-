"""
ASGI config for spam_detector project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

from channels.routing import ProtocolTypeRouter,URLRouter
from django.core.asgi import get_asgi_application
from django.urls import path
from detector.consumers import MyConsumer

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "spam_detector.settings")

# application = get_asgi_application()
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket":URLRouter([
     path('practice/', MyConsumer.as_asgi())
])
    # Just HTTP for now. (We can add other protocols later.)
})