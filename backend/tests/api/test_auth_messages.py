import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.auth import RegisterRequest, login, register


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def first(self):
        return self._value

    def all(self):
        if isinstance(self._value, list):
            return self._value
        return [self._value] if self._value is not None else []


class _FakeExecuteResult:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return _FakeScalarResult(self._value)


class _FakeAsyncSession:
    def __init__(self, execute_results):
        self._execute_results = list(execute_results)

    async def execute(self, _query):
        return _FakeExecuteResult(self._execute_results.pop(0))

    async def commit(self):
        return None

    async def refresh(self, _instance):
        return None

    def add(self, _instance):
        return None


class _FakeOAuthForm:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password


class _FakeUser:
    def __init__(self, *, email="demo@example.com", hashed_password="hashed", is_active=True):
        self.id = "user-1"
        self.email = email
        self.hashed_password = hashed_password
        self.full_name = "Demo"
        self.is_active = is_active
        self.is_superuser = False
        self.role = "member"


@pytest.mark.asyncio
async def test_login_invalid_credentials_message(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.auth.security.verify_password", lambda plain, hashed: False)

    db = _FakeAsyncSession([_FakeUser()])
    form = _FakeOAuthForm("demo@example.com", "bad-password")

    with pytest.raises(HTTPException) as exc_info:
        await login(db=db, form_data=form)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "邮箱或密码错误"


@pytest.mark.asyncio
async def test_login_inactive_user_message(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.auth.security.verify_password", lambda plain, hashed: True)

    db = _FakeAsyncSession([_FakeUser(is_active=False)])
    form = _FakeOAuthForm("demo@example.com", "password")

    with pytest.raises(HTTPException) as exc_info:
        await login(db=db, form_data=form)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "账户已被禁用"


@pytest.mark.asyncio
async def test_register_existing_email_message():
    db = _FakeAsyncSession([_FakeUser(email="demo@example.com")])

    with pytest.raises(HTTPException) as exc_info:
        await register(
            db=db,
            user_in=RegisterRequest(
                email="demo@example.com",
                password="password123",
                full_name="Demo",
            ),
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "该邮箱已被注册"


@pytest.mark.asyncio
async def test_register_first_user_allowed_when_public_registration_disabled(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.auth.settings.ALLOW_PUBLIC_REGISTRATION", False)
    monkeypatch.setattr("app.api.v1.endpoints.auth.security.get_password_hash", lambda password: "hashed")
    db = _FakeAsyncSession([None, []])

    user = await register(
        db=db,
        user_in=RegisterRequest(
            email="admin@example.com",
            password="password123",
            full_name="Admin",
        ),
    )

    assert user.is_superuser is True
    assert user.role == "admin"


@pytest.mark.asyncio
async def test_register_rejected_when_public_registration_disabled(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.auth.settings.ALLOW_PUBLIC_REGISTRATION", False)
    db = _FakeAsyncSession([None, [_FakeUser()]])

    with pytest.raises(HTTPException) as exc_info:
        await register(
            db=db,
            user_in=RegisterRequest(
                email="new@example.com",
                password="password123",
                full_name="New User",
            ),
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "公开注册已关闭，请联系管理员创建账户"


@pytest.mark.asyncio
async def test_register_allowed_when_public_registration_enabled(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.auth.settings.ALLOW_PUBLIC_REGISTRATION", True)
    monkeypatch.setattr("app.api.v1.endpoints.auth.security.get_password_hash", lambda password: "hashed")
    db = _FakeAsyncSession([None, [_FakeUser()]])

    user = await register(
        db=db,
        user_in=RegisterRequest(
            email="new@example.com",
            password="password123",
            full_name="New User",
        ),
    )

    assert user.is_superuser is False
    assert user.role == "member"
