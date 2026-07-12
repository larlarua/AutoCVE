import pytest

from app.services import scanner


@pytest.mark.asyncio
async def test_get_github_branches_fetches_all_pages(monkeypatch):
    first_page = [{"name": f"branch-{index}"} for index in range(100)]
    second_page = [{"name": "branch-100"}]
    responses = [first_page, second_page]
    calls = []

    async def fake_github_api(url, token=None):
        calls.append((url, token))
        return responses.pop(0)

    monkeypatch.setattr(scanner, "github_api", fake_github_api)

    branches = await scanner.get_github_branches(
        "https://github.com/example/project",
        token="token",
    )

    assert len(branches) == 101
    assert branches[0] == "branch-0"
    assert branches[-1] == "branch-100"
    assert "page=1" in calls[0][0]
    assert "page=2" in calls[1][0]
    assert [token for _, token in calls] == ["token", "token"]
