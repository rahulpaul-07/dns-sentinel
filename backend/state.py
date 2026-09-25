"""Shared in-process runtime state for the DNSentinel backend.

Routers and services share these live objects (telemetry deques, per-IP query
history, the SSE/WebSocket connection manager). All objects are mutated in
place -- never rebound -- so importing them by name is safe across modules.

This state is per-process by design: run a single worker, or move it to Redis
before scaling horizontally.
"""
import asyncio
import time
from collections import OrderedDict, deque

from fastapi import WebSocket

# Rolling operational buffers (bounded so memory stays flat under load).
traffic_history: deque = deque(maxlen=200)
alerts: deque = deque(maxlen=100)
ip_query_history: "OrderedDict[str, deque]" = OrderedDict()
alert_groups: dict = {}

MAX_TRACKED_IPS = 10_000
FREQUENCY_WINDOW_S = 60
SSE_QUEUE_SIZE = 256

# Risk tiers accepted by filtering endpoints (mirrors RiskEngine tiers).
VALID_RISK_LEVELS = {"Low", "Medium", "High", "Critical"}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.sse_queues: list[asyncio.Queue] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def new_sse_queue(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=SSE_QUEUE_SIZE)
        self.sse_queues.append(queue)
        return queue

    def drop_sse_queue(self, queue: asyncio.Queue):
        if queue in self.sse_queues:
            self.sse_queues.remove(queue)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)
        # Never await a slow consumer: a stalled browser tab must not stall
        # ingestion. When a client's buffer is full, drop its oldest event.
        for queue in list(self.sse_queues):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(message)


manager = ConnectionManager()


def record_query(ip: str, ts: float) -> int:
    """Record a query from `ip` at `ts`; return its count in the last minute."""
    history = ip_query_history.get(ip)
    if history is None:
        history = ip_query_history[ip] = deque(maxlen=5000)
        if len(ip_query_history) > MAX_TRACKED_IPS:
            ip_query_history.popitem(last=False)
    ip_query_history.move_to_end(ip)
    history.append(ts)
    now = max(time.time(), ts)
    while history and now - history[0] >= FREQUENCY_WINDOW_S:
        history.popleft()
    return len(history)
