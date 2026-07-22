from __future__ import annotations

import inspect
from typing import Any, Optional

from app.core.config import settings

TALOS_AUDIT_JOB_NAME = "run_talos_audit"


class TalosAuditQueue:
    """Enqueue Talos jobs on the existing agent-worker ARQ queue."""

    def __init__(self, *, arq_pool: Optional[Any] = None, redis_url: Optional[str] = None):
        self.arq_pool = arq_pool
        self.redis_url = redis_url or settings.REDIS_URL
        self._owns_pool = arq_pool is None

    async def _pool(self):
        if self.arq_pool is None:
            from arq import create_pool
            from arq.connections import RedisSettings

            self.arq_pool = await create_pool(
                RedisSettings.from_dsn(self.redis_url),
                default_queue_name=settings.AGENT_TASK_QUEUE_NAME,
            )
        return self.arq_pool

    async def enqueue(self, job_id: str) -> None:
        pool = await self._pool()
        await pool.enqueue_job(
            TALOS_AUDIT_JOB_NAME,
            str(job_id),
            _job_id=f"talos-audit:{job_id}",
            _queue_name=settings.AGENT_TASK_QUEUE_NAME,
        )

    async def close(self) -> None:
        if not self._owns_pool or self.arq_pool is None:
            return
        close = getattr(self.arq_pool, "close", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result


async def enqueue_talos_audit_job(job_id: str) -> None:
    queue = TalosAuditQueue()
    try:
        await queue.enqueue(job_id)
    finally:
        await queue.close()
