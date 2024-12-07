from channels.generic.websocket import AsyncWebsocketConsumer
import json

class ScanNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection
        await self.accept()

    async def send_notification(self, event):
        # Send a message to the WebSocket
        await self.send(text_data=json.dumps({
            'message': event['message']
        }))
