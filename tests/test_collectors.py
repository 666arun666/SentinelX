# ruff: noqa: ASYNC230, SIM115
import asyncio
import os
import sys
import tempfile

import pytest

from sentinelx.collection.file_collector import FileCollector


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows prevents renaming open files; this test validates Linux inode-based log rotation",
)
async def test_file_collector_rotation():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.log")
        with open(test_file, "w") as f:
            f.write("line 1\n")

        queue = asyncio.Queue()
        collector = FileCollector("test_source", test_file, queue, poll_interval=0.1)

        task = asyncio.create_task(collector.start())

        # Read first event
        event1 = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert event1["raw_log"] == "line 1"
        queue.task_done()

        # Rename / create rotation
        os.rename(test_file, test_file + ".1")
        with open(test_file, "w") as f:
            f.write("line 2\n")

        event2 = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert event2["raw_log"] == "line 2"
        queue.task_done()

        collector.stop()
        await task


@pytest.mark.asyncio
async def test_file_collector_partial_lines():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.log")
        with open(test_file, "w") as f:
            f.write("partial ")

        queue = asyncio.Queue()
        collector = FileCollector("test_source", test_file, queue, poll_interval=0.1)

        task = asyncio.create_task(collector.start())

        # Write rest of line
        await asyncio.sleep(0.2)
        with open(test_file, "a") as f:
            f.write("line\n")

        event = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert event["raw_log"] == "partial line"
        queue.task_done()

        collector.stop()
        await task


@pytest.mark.asyncio
async def test_backpressure_observability():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.log")
        with open(test_file, "w") as f:
            f.write("event 1\n")

        # Create a tiny queue bounded to 1
        queue = asyncio.Queue(maxsize=1)
        collector = FileCollector("test_source", test_file, queue, poll_interval=0.1)

        # We don't start the collector task because we want to manually control execution
        # to ensure the queue hits max capacity.
        # Let's run a single iteration manually via _read_to_eof
        fd = open(test_file, "r", encoding="utf-8")

        # enqueue "event 1"
        await collector._process_data(fd.read())
        assert queue.qsize() == 1
        assert queue.full()
        assert collector.metrics["events_read"] == 1
        assert collector.metrics.get("backpressure_events", 0) == 0

        # Now attempt to write a second event which should trigger backpressure
        with open(test_file, "a") as f:
            f.write("event 2\n")

        fd.seek(0)

        # Enqueue event 2, which will block. We use wait_for to prove it blocks
        task = asyncio.create_task(collector._process_data("event 2\n"))

        # Give it a tiny moment to hit the block
        await asyncio.sleep(0.1)

        assert queue.qsize() == 1  # Still 1, task is waiting
        assert collector.metrics["backpressure_events"] == 1  # Metric incremented!

        # Now free capacity
        event1 = await queue.get()
        assert event1["raw_log"] == "event 1"
        queue.task_done()

        # Task should now complete
        await asyncio.wait_for(task, timeout=1.0)

        event2 = await queue.get()
        assert event2["raw_log"] == "event 2"
        queue.task_done()

        fd.close()
