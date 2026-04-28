from app.services.agent.agents.finding_skill_protocol import build_finding_skill_protocol


def test_finding_skill_protocol_uses_runtime_tool_names_only():
    protocol = build_finding_skill_protocol()

    for tool_name in ("Read", "Glob", "Grep", "Write", "Skill", "Bash", "PowerShell"):
        assert tool_name in protocol

    for legacy_name in ("read_file", "list_files", "read_many_files", "Action Batch"):
        assert legacy_name not in protocol

    assert "Finding 技能使用协议" in protocol
    assert "Bootstrap the current primary audit skill" not in protocol
    assert "Do not rely on scanner-style tools" not in protocol
