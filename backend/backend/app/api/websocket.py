"""
ThreatVision AI — WebSocket Manager
Broadcasts real-time pipeline progress to connected frontend clients.

Each investigation has its own connection set.
The pipeline worker calls ws_manager.broadcast() as each stage completes.

Usage from pipeline:
    await ws_manager.broadcast(investigation_id, PipelineUpdate(...))

Usage from FastAPI route:
    @app.websocket("/ws/{investigation_id}")
    async def ws_endpoint(ws: WebSocket, investigation_id: str):
        await ws_manager.connect(ws, investigation_id)
        try:
            await ws_manager.listen(ws, investigation_id)
        finally:
            ws_manager.disconnect(ws, investigation_id)
"""

import asyncio
from collections import defaultdict
from typing import Dict, Set

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from backend.app.schemas.investigation import PipelineUpdate

log = structlog.get_logger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections grouped by investigation_id.
    Thread-safe via asyncio (single-threaded event loop).
    """

    def __init__(self):
        # investigation_id → set of active WebSocket connections
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)

    async def connect(self, websocket: WebSocket, investigation_id: str) -> None:
        await websocket.accept()
        self._connections[investigation_id].add(websocket)
        log.info(
            "ws.client_connected",
            investigation_id=investigation_id,
            total=len(self._connections[investigation_id]),
        )

    def disconnect(self, websocket: WebSocket, investigation_id: str) -> None:
        self._connections[investigation_id].discard(websocket)
        if not self._connections[investigation_id]:
            del self._connections[investigation_id]
        log.info(
            "ws.client_disconnected",
            investigation_id=investigation_id,
        )

    async def broadcast(
        self,
        investigation_id: str,
        update: PipelineUpdate,
    ) -> None:
        """Send a PipelineUpdate to all clients watching this investigation."""
        connections = self._connections.get(investigation_id, set())
        if not connections:
            return

        payload = update.model_dump_json()
        dead: Set[WebSocket] = set()

        for ws in list(connections):
            try:
                await ws.send_text(payload)
            except Exception as exc:
                log.warning(
                    "ws.send_failed",
                    investigation_id=investigation_id,
                    error=str(exc),
                )
                dead.add(ws)

        # Clean up broken connections
        for ws in dead:
            self.disconnect(ws, investigation_id)

    async def send_error(
        self,
        investigation_id: str,
        error_message: str,
    ) -> None:
        """Broadcast an error event to all clients."""
        connections = self._connections.get(investigation_id, set())
        payload = f'{{"event":"error","investigation_id":"{investigation_id}","message":"{error_message}"}}'
        for ws in list(connections):
            try:
                await ws.send_text(payload)
            except Exception:
                pass

    async def listen(self, websocket: WebSocket, investigation_id: str) -> None:
        """
        Keep the WebSocket alive, responding to ping messages.
        Exits cleanly on disconnect.
        """
        try:
            while True:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=60.0,
                )
                if data == "ping":
                    await websocket.send_text('{"event":"pong"}')
        except (WebSocketDisconnect, asyncio.TimeoutError):
            pass

    @property
    def active_count(self) -> int:
        return sum(len(v) for v in self._connections.values())


# Module-level singleton shared across the application
ws_manager = ConnectionManager()
