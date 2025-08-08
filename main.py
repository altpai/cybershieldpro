from fastapi import FastAPI, Request
from fastapi.responses import Response
import httpx
import asyncio

# Routers
from controls.logs_management.dev.routes.lgn_log_routes import router as lgn_log_router
from controls.CSP001_credential_stuffing_detection.dev.detection_logic_v1 import router as cred_stuff_router
from controls.ws.websocket_routes import register_websocket_route
from controls.CSP001_credential_stuffing_detection.dev.routes.wp_db_monitoring import monitor_db_credential_stuffing_detection

app = FastAPI()

# Register WebSocket route
register_websocket_route(app)

# Include routers
app.include_router(lgn_log_router)
app.include_router(cred_stuff_router)

# Startup tasks
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(monitor_db_credential_stuffing_detection())

# Health check
@app.get("/")
async def root():
    return {"message": "Detection Service Runningman"}
