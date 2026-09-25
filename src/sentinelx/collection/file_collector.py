import asyncio
import os

import structlog

from sentinelx.collection.base import BaseCollector

logger = structlog.get_logger(__name__)


class FileCollector(BaseCollector):
    def __init__(
        self,
        source_name: str,
        file_path: str,
        queue: asyncio.Queue,
        initial_inode: int | None = None,
        initial_offset: int = 0,
        poll_interval: float = 1.0,
    ):
        super().__init__(source_name, queue)
        self.file_path = file_path
        self.current_inode = initial_inode
        self.current_offset = initial_offset
        self.poll_interval = poll_interval

    async def start(self) -> None:
        logger.info(
            "file_collector_started", source=self.source_name, path=self.file_path
        )
        fd = None

        while not self._stop_event.is_set():
            if not os.path.exists(self.file_path):
                if fd is not None:
                    fd.close()
                    fd = None
                await asyncio.sleep(self.poll_interval)
                continue

            try:
                if fd is None:
                    try:
                        fd = open(  # noqa: ASYNC230, SIM115
                            self.file_path, "r", encoding="utf-8", errors="replace"
                        )
                        st = os.fstat(fd.fileno())
                        self.current_inode = st.st_ino
                        # Fast forward to offset if valid
                        if self.current_offset > 0:
                            if st.st_size < self.current_offset:
                                # Truncated, reset
                                self.current_offset = 0
                            else:
                                fd.seek(self.current_offset)
                    except Exception as e:  # noqa: BLE001
                        logger.warning(
                            "file_open_failed", path=self.file_path, error=str(e)
                        )
                        await asyncio.sleep(self.poll_interval)
                        continue

                last_offset = fd.tell()
                line = fd.readline()
                if not line:
                    # EOF, check rotation
                    st = os.stat(self.file_path)
                    if st.st_ino != self.current_inode:
                        logger.info("file_rotated", source=self.source_name)
                        fd.close()
                        fd = None
                        self.current_offset = 0
                    else:
                        # Sleep before retry
                        await asyncio.sleep(self.poll_interval / 10.0)
                    continue

                if not line.endswith("\n") and not line.endswith("\r\n"):
                    # Partial line, revert offset and wait
                    fd.seek(last_offset)
                    await asyncio.sleep(self.poll_interval / 10.0)
                    continue

                self.current_offset = fd.tell()

                payload = {
                    "source": self.source_name,
                    "raw_log": line.strip(),
                    "position_identity": self.current_offset,
                    "file_inode": self.current_inode,
                }
                self.metrics["events_read"] += 1
                await self.enqueue_payload(payload)

            except Exception as e:  # noqa: BLE001
                logger.error("file_collection_error", error=str(e))
                if fd is not None:
                    fd.close()
                    fd = None
                await asyncio.sleep(self.poll_interval)

        if fd is not None:
            fd.close()

    async def _process_data(self, chunk: str) -> None:
        """Method exposed for M2 tests."""
        for line in chunk.splitlines(keepends=True):
            if not line.endswith("\n") and not line.endswith("\r\n"):
                continue
            payload = {
                "source": self.source_name,
                "raw_log": line.strip(),
                "position_identity": self.current_offset,
                "file_inode": self.current_inode,
            }
            self.metrics["events_read"] += 1
            await self.enqueue_payload(payload)

    def get_metrics(self) -> dict:
        base = super().get_metrics()
        base.update({"offset": self.current_offset, "inode": self.current_inode})
        return base
