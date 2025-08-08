# websocket_manager.py
import asyncio
from typing import Dict, List
from fastapi import WebSocket

class WebSocketManager:
    def __init__(self):
        self.active_groups: Dict[str, List[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, group_key: str):
        await websocket.accept()
        async with self.lock:
            self.active_groups.setdefault(group_key, []).append(websocket)

    async def disconnect(self, websocket: WebSocket, group_key: str):
        async with self.lock:
            if group_key in self.active_groups and websocket in self.active_groups[group_key]:
                self.active_groups[group_key].remove(websocket)
                if not self.active_groups[group_key]:
                    del self.active_groups[group_key]

    async def send_message(self, group_key: str, message: dict):
        async with self.lock:
            for conn in self.active_groups.get(group_key, []):
                try:
                    await conn.send_json(message)
                except Exception as e:
                    print(f"WebSocket send error: {e}")

# Singleton instance to use across app
ws_manager = WebSocketManager()
