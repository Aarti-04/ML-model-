# from channels.routing import ProtocolTypeRouter, URLRouter
# from django.urls import path
# from detector.consumers import MyConsumer
# application = ProtocolTypeRouter({
#     'websocket': URLRouter([
#         path('ws/chat/', MyConsumer.as_asgi()),
#     ])
# })
# from django.urls import re_path
# from . import consumers
# websocket_urlPatterns=[re_path(r'ws/socket-server/',consumers.demoConsumer.as_asgi())]