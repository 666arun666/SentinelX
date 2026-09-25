import asyncio
import json

import structlog

from sentinelx.collection.base import BaseCollector

logger = structlog.get_logger(__name__)


class JournalCollector(BaseCollector):
    """
    Asynchronous journalctl collector.
    Reads journald events as JSON. Uses cursor for state.
    """

    def __init__(
        self, source_name: str, queue: asyncio.Queue, initial_cursor: str | None = None
    ):
        super().__init__(source_name, queue)
        self.cursor = initial_cursor
        self.process = None

    async def _run(self) -> None:
        backoff = 1.0

        while not self._stop_event.is_set():
            cmd = ["journalctl", "-o", "json", "--follow"]
            if self.cursor:
                cmd.extend(["--after-cursor", self.cursor])

            logger.info(
                "starting_journalctl", source=self.source_name, cursor=self.cursor
            )

            try:
                self.process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                # Successful start, reset backoff
                backoff = 1.0

                while not self._stop_event.is_set():
                    line = await self.process.stdout.readline()
                    if not line:
                        break  # stream ended

                    try:
                        raw_event = line.decode("utf-8").strip()
                        if not raw_event:
                            continue

                        # Quick parse to extract cursor for position identity
                        # The manager will do full parsing later, but we need the cursor now
                        # to act as position_identity
                        parsed = json.loads(raw_event)
                        new_cursor = parsed.get("__CURSOR")

                        if new_cursor:
                            self.cursor = new_cursor

                        self.metrics["events_read"] += 1
                        payload = {
                            "source": self.source_name,
                            "raw_log": raw_event,
                            "position_identity": self.cursor,
                        }
                        # Blocking put handles backpressure and tracks metrics
                        await self.enqueue_payload(payload)

                    except json.JSONDecodeError:
                        logger.warning(
                            "journal_malformed_json", source=self.source_name
                        )
                        # We log and continue, we do not crash
                        continue

                # If stream ends unexpectedly
                return_code = await self.process.wait()
                logger.warning(
                    "journalctl_exited",
                    source=self.source_name,
                    return_code=return_code,
                )

            except FileNotFoundError:
                logger.error("journalctl_not_found", source=self.source_name)
                # No journalctl, wait a long time before retrying to avoid spam
                await asyncio.sleep(60.0)
            except Exception as e:  # noqa: BLE001
                logger.error("journalctl_error", source=self.source_name, error=str(e))

            if not self._stop_event.is_set():
                self.metrics["reconnects"] += 1
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)  # exp backoff max 60s

    def stop(self) -> None:
        super().stop()
        if self.process and self.process.returncode is None:
            try:
                self.process.terminate()
            except Exception:  # noqa: BLE001, S110
                pass  # Process may already be dead
