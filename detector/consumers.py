# from channels.generic.websocket import AsyncWebsocketConsumer,WebsocketConsumer
# # # import json
# # # from channels.generic.websocket import WebsocketConsumer
# # import json
# class PracticeConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#            await self.accept()
#     async def disconnect(self, code):
#         pass
#     async def receive(self, text_data=None, bytes_data=None, **kwargs):
#         print("hello")
#         self.send("hello world")
#         if text_data == 'PING':
#              print("in ping")
#              await self.send('hello')
# # class demoConsumer(WebsocketConsumer):
# #      def connect(self):
# #            self.accept()
# #            self.send(text_data=json.dumps({'type':'connection_established','message':'you are now connected'}))
# # # class ChatConsumer(WebsocketConsumer):
# # #     def connect(self):
# # #         self.accept()
# # #     def disconnect(self, close_code):
# # #         pass
# # #     def receive(self, text_data):
# # #         text_data_json = json.loads(text_data)
# # #         message = text_data_json['message']
# # #         self.send(text_data=json.dumps({
# # #             'message': message
# # #         }))


# # # myapp/consumers.py

# # # from channels.generic.websocket import AsyncWebsocketConsumer

# # # class MyConsumer(AsyncWebsocketConsumer):
# # #     async def connect(self):
# # #         await self.accept()

# # #     async def disconnect(self, close_code):
# # #         pass

# # #     async def receive(self, text_data):
# # #         # Handle received data here
# # #         pass

from channels.generic.websocket import AsyncWebsocketConsumer
import requests as customRequest
 

class MyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        print("WebSocket connection established.")
        # res= customRequest.get("http://127.0.0.1:8000/api/mailread/")
        # print("res",res.json())
        await self.send(text_data="Mail Read")


    async def disconnect(self, close_code):
        print("WebSocket connection closed.")

    async def receive(self, text_data):
        print("Received message:", text_data)