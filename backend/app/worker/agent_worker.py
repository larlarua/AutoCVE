from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from arq.connections import RedisSettings
from arq.worker import func

from app.core.config import settings
from app.services.agent.task_executor import execute_agent_task
from app.services.agent.task_queue import AGENT_TASK_JOB_NAME
from app.services.talos_audit.runner import run_talos_audit_job
from app.services.talos_audit.task_queue import TALOS_AUDIT_JOB_NAME

logger = logging.getLogger(__name__)


def decode_task_payload(payload: Any) -> str:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    try:
        data = json.loads(str(payload))
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid agent task payload") from exc
    task_id = str(data.get("task_id") or "").strip() if isinstance(data, dict) else ""
    if not task_id:
        raise ValueError("Agent task payload missing task_id")
    return task_id


async def run_worker() -> None:
    from arq.worker import Worker

    logging.basicConfig(level=logging.INFO)
    worker = Worker(
        WorkerSettings.functions,
        queue_name=WorkerSettings.queue_name,
        redis_settings=WorkerSettings.redis_settings,
        max_jobs=WorkerSettings.max_jobs,
        job_timeout=WorkerSettings.job_timeout,
        max_tries=WorkerSettings.max_tries,
        retry_jobs=WorkerSettings.retry_jobs,
    )
    await worker.async_run()


async def execute_agent_task_job(ctx: dict[str, Any], task_id: str) -> None:
    logger.info("Agent worker picked task %s", task_id)
    await execute_agent_task(task_id)


async def execute_talos_audit_job(ctx: dict[str, Any], job_id: str) -> None:
    logger.info("Agent worker picked Talos audit job %s", job_id)
    await run_talos_audit_job(job_id)


class WorkerSettings:
    functions = [
        func(execute_agent_task_job, name=AGENT_TASK_JOB_NAME),
        func(execute_talos_audit_job, name=TALOS_AUDIT_JOB_NAME),
    ]
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    queue_name = settings.AGENT_TASK_QUEUE_NAME
    max_jobs = settings.AGENT_WORKER_CONCURRENCY
    job_timeout = settings.AGENT_WORKER_JOB_TIMEOUT_SECONDS
    max_tries = settings.AGENT_WORKER_MAX_TRIES
    retry_jobs = True


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
