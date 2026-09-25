from __future__ import annotations

from sentinelx.utils.logging import configure_logging, get_logger


def test_get_logger_returns_bound_logger() -> None:
    log = get_logger("sentinelx.test")
    assert log is not None
    # Should not raise, and should accept structured kwargs.
    log.info("test.event", foo="bar", count=1)


def test_configure_logging_is_idempotent() -> None:
    configure_logging(level="DEBUG")
    configure_logging(level="DEBUG")  # second call should be a no-op, not raise
