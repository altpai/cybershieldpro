from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from controls.ws.websocket_manager import ws_manager

def register_websocket_route(app: FastAPI):
    @app.websocket("/ws/{group_key}")
    async def websocket_endpoint(websocket: WebSocket, group_key: str):
        await ws_manager.connect(websocket, group_key)
        try:
            while True:
                try:
                    message = await websocket.receive_text()
                    if message.lower() == "ping":
                        # Optional: handle ping message if needed
                        continue
                except WebSocketDisconnect:
                    print(f"WebSocket disconnected: group={group_key}")
                    break
                except RuntimeError as e:
                    print(f"Runtime error on group {group_key}: {e}")
                    break
                except Exception as e:
                    print(f"Unexpected error from client ({group_key}): {e}")
                    break
        finally:
            await ws_manager.disconnect(websocket, group_key)
