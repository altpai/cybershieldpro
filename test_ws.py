import asyncio
import websockets
import json

async def keep_alive(group_key="test-api-key"):
    uri = f"ws://localhost:8000/ws/{group_key}"

    while True:  # reconnect loop
        try:
            print(f"Connecting to {uri}...")
            async with websockets.connect(uri) as websocket:
                print("✅ Connected")

                async def heartbeat():
                    while True:
                        await asyncio.sleep(30)
                        try:
                            await websocket.send("ping")
                        except Exception:
                            break

                async def receiver():
                    while True:
                        try:
                            message = await websocket.recv()
                            try:
                                data = json.loads(message)
                                print(f"📩 Received JSON message: {data}")
                            except json.JSONDecodeError:
                                print(f"📩 Received non-JSON message: {message}")
                        except websockets.ConnectionClosed:
                            print("❌ Connection closed by server")
                            break
                        except Exception as e:
                            print(f"⚠️ Error receiving message: {e}")
                            break

                await asyncio.gather(heartbeat(), receiver())

        except Exception as e:
            print(f"❌ Connection lost: {e}")
            print("Reconnecting in 5 seconds...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(keep_alive())
