from datetime import UTC, datetime

import pytest

from sentinelx.detection.engine import DetectionEngine
from sentinelx.detection.rules import Rule
from sentinelx.models.event import NormalizedEvent


def test_rule_exact_match():
    r = Rule(
        rule_id="1",
        title="Exact",
        severity="high",
        logsource="all",
        selection={"command": "sudo ls"},
        condition="selection",
    )
    # Exact match works
    assert r.matches({"command": "sudo ls"})[0] is True
    # Non-match fails
    assert r.matches({"command": "sudo cat"})[0] is False


def test_rule_substring_match():
    r = Rule(
        rule_id="2",
        title="Sub",
        severity="low",
        logsource="all",
        selection={"message": "*failed*"},
        condition="selection",
    )
    # Substring match works
    assert r.matches({"message": "login failed for user"})[0] is True
    # Miss fails
    assert r.matches({"message": "login success"})[0] is False


def test_rule_regex_match():
    r = Rule(
        rule_id="3",
        title="Regex",
        severity="critical",
        logsource="all",
        selection={"process": "/^(sshd|sudo)$/"},
        condition="selection",
    )
    assert r.matches({"process": "sshd"})[0] is True
    assert r.matches({"process": "sudo"})[0] is True
    assert r.matches({"process": "bash"})[0] is False
    assert r.matches({"process": "sshd2"})[0] is False


def test_rule_list_match():
    r = Rule(
        rule_id="4",
        title="List",
        severity="medium",
        logsource="all",
        selection={"user": ["root", "admin"]},
        condition="selection",
    )
    assert r.matches({"user": "root"})[0] is True
    assert r.matches({"user": "admin"})[0] is True
    assert r.matches({"user": "guest"})[0] is False


def test_rule_malformed_severity():
    with pytest.raises(ValueError, match="Invalid severity"):
        Rule(
            rule_id="bad",
            title="T",
            severity="unknown",
            logsource="all",
            selection={},
            condition="selection",
        )


def test_missing_event_fields():
    r = Rule(
        rule_id="5",
        title="Missing",
        severity="low",
        logsource="all",
        selection={"target": "system"},
        condition="selection",
    )
    assert r.matches({"other": "system"})[0] is False


def test_engine_finding_id_deduplication():
    engine = DetectionEngine("nonexistent_dir")
    fid1 = engine._generate_finding_id("rule_A", "event_1")
    fid2 = engine._generate_finding_id("rule_A", "event_1")
    fid3 = engine._generate_finding_id("rule_B", "event_1")

    assert fid1 == fid2
    assert fid1 != fid3


@pytest.mark.asyncio
async def test_engine_rule_evaluation_failure_isolation(mocker):
    engine_obj = DetectionEngine("nonexistent_dir")

    # Inject mock rule that raises exception
    bad_rule = mocker.Mock()
    bad_rule.logsource = "all"
    bad_rule.matches.side_effect = Exception("Crash during matching")
    bad_rule.rule_id = "bad_rule"

    engine_obj.all_source_rules.append(bad_rule)

    event = NormalizedEvent(
        event_id="evt1",
        event_time=datetime.now(UTC),
        collected_at=datetime.now(UTC),
        source="syslog",
        raw_log="test",
    )

    # Should not raise exception
    await engine_obj.evaluate_event(event)


@pytest.mark.asyncio
async def test_persistence_isolation(mocker):
    engine_obj = DetectionEngine("nonexistent_dir")

    # Inject valid rule
    r = Rule(
        rule_id="test_persist",
        title="Persist",
        severity="low",
        logsource="all",
        selection={"raw_log": "trigger"},
        condition="selection",
    )
    engine_obj.all_source_rules.append(r)

    event = NormalizedEvent(
        event_id="evt2",
        event_time=datetime.now(UTC),
        collected_at=datetime.now(UTC),
        source="syslog",
        raw_log="trigger",
    )

    # Force DB to fail inside persist_findings
    mocker.patch.object(
        engine_obj, "_persist_findings", side_effect=Exception("DB Offline")
    )

    # evaluate_event should isolate persistence failure so it doesn't bubble to caller!
    # Wait, in engine.py evaluate_event: `await self._persist_findings(...)` is NOT wrapped in try-except!
    # The requirement: "A finding database failure must be observable and retryable according to the M3 design... detection failure does not stop M2 persistence."
    # If `_persist_findings` throws, `_consume_detection_queue` catches it and logs it!
    # So `evaluate_event` WILL raise, but `_consume_detection_queue` isolates it from CollectionManager.
    with pytest.raises(Exception, match="DB Offline"):
        await engine_obj.evaluate_event(event)


@pytest.mark.asyncio
async def test_finding_persistence_integration():
    import uuid
    from datetime import UTC, datetime

    from sqlalchemy import select

    from sentinelx.core.db import AsyncSessionLocal, persist_events_and_cursor
    from sentinelx.models.db_models import Finding

    engine_obj = DetectionEngine("nonexistent_dir")

    unique_id = str(uuid.uuid4())

    event_dict = {
        "event_id": unique_id,
        "event_time": datetime.now(UTC),
        "collected_at": datetime.now(UTC),
        "source": "auth.log",
        "raw_log": "test line sshd Failed password for user",
    }

    async with AsyncSessionLocal() as session:
        await persist_events_and_cursor(session, event_dict, "auth.log", "300")

    event = NormalizedEvent(**event_dict)

    r = Rule(
        rule_id="test_ssh_rule",
        title="SSH Fail",
        severity="high",
        logsource="all",
        selection={"raw_log": "*Failed password*"},
        condition="selection",
    )
    engine_obj.all_source_rules.append(r)

    await engine_obj.evaluate_event(event)

    async with AsyncSessionLocal() as session:
        stmt = select(Finding).where(Finding.event_id == unique_id)
        result = await session.execute(stmt)
        findings = result.scalars().all()
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "test_ssh_rule"
        assert f.severity == "high"
        assert f.title == "SSH Fail"
        assert "raw_log" in f.evidence["matched_fields"]

    await engine_obj.evaluate_event(event)

    async with AsyncSessionLocal() as session:
        stmt = select(Finding).where(Finding.event_id == unique_id)
        result = await session.execute(stmt)
        findings = result.scalars().all()
        assert len(findings) == 1

    r2 = Rule(
        rule_id="test_ssh_rule_2",
        title="SSH Fail 2",
        severity="low",
        logsource="all",
        selection={"raw_log": "*Failed password*"},
        condition="selection",
    )
    engine_obj.all_source_rules.append(r2)

    await engine_obj.evaluate_event(event)

    async with AsyncSessionLocal() as session:
        stmt = select(Finding).where(Finding.event_id == unique_id)
        result = await session.execute(stmt)
        findings = result.scalars().all()
        assert len(findings) == 2
