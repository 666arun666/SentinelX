from sentinelx.collection.parsers import (
    parse_auditd,
    parse_auth_log,
    parse_journal_json,
    parse_syslog_timestamp,
)


def test_parse_syslog_timestamp():
    # Example: "Oct 12 10:11:12"
    dt = parse_syslog_timestamp("Oct 12 10:11:12")
    assert dt.month == 10
    assert dt.day == 12
    assert dt.hour == 10


def test_parse_auth_log_sshd():
    raw = "Oct 12 10:11:12 host1 sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2"
    parsed = parse_auth_log(raw)
    assert parsed["hostname"] == "host1"
    assert parsed["process"] == "sshd"
    assert parsed["event_type"] == "authentication_failed"
    assert parsed["username"] == "root"
    assert parsed["source_ip"] == "192.168.1.1"


def test_parse_auth_log_sudo():
    raw = "Oct 12 10:11:12 host1 sudo:  user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls"
    parsed = parse_auth_log(raw)
    assert parsed["process"] == "sudo"
    assert parsed["event_type"] == "sudo"
    assert parsed["command"] == "/bin/ls"


def test_parse_journal_json():
    raw = '{"MESSAGE": "Test message", "_HOSTNAME": "host1", "_COMM": "systemd", "__CURSOR": "s=123", "__REALTIME_TIMESTAMP": "1610000000000000"}'
    parsed = parse_journal_json(raw)
    assert parsed["message"] == "Test message"
    assert parsed["hostname"] == "host1"
    assert parsed["process"] == "systemd"
    assert parsed["_cursor"] == "s=123"


def test_parse_auditd():
    raw = 'type=SYSCALL msg=audit(1610000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffe123 a1=7ffe456 a2=7ffe789 a3=8 items=2 ppid=123 pid=456 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="ls" exe="/usr/bin/ls" key="system-audit"'
    parsed = parse_auditd(raw)
    assert parsed["event_type"] == "audit"
    assert parsed["command"] == "ls"
    assert parsed["file_path"] == "/usr/bin/ls"
    assert parsed.get("severity") is None
