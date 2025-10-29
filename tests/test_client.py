import pytest
import responses
from generic_integration_client import GenericIntegrationClient
from generic_integration_client.exceptions import AuthenticationError


@responses.activate
def test_static_headers_auth():
    responses.get(
        "https://api.test.com/data",
        json={"ok": True},
        status=200,
        match=[
            responses.matchers.header_matcher({
                "email": "user@test.com",
                "senha": "123456",
                "Accept": "application/json"
            })
        ]
    )

    client = GenericIntegrationClient(
        base_url="https://api.test.com",
        auth_method="static_headers",
        auth_config={
            "headers": {
                "email": "user@test.com",
                "senha": "123456",
                "Accept": "application/json"
            }
        }
    )
    result = client.get("/data")
    assert result == {"ok": True}

@responses.activate
def test_static_bearer():
    responses.get("https://api.test.com/data", json={"ok": True}, status=200)
    client = GenericIntegrationClient(
        base_url="https://api.test.com",
        auth_method="static_bearer",
        auth_config={"token": "abc123"}
    )
    result = client.get("/data")
    assert result == {"ok": True}

@responses.activate
def test_bearer_user_pass_flow():
    responses.post("https://api.test.com/auth/login", json={"access_token": "xyz789"})
    responses.get("https://api.test.com/users", json=[{"id": 1}], status=200)
    client = GenericIntegrationClient(
        base_url="https://api.test.com",
        auth_method="bearer_user_pass",
        auth_config={"username": "u", "password": "p"}
    )
    result = client.get("/users")
    assert result == [{"id": 1}]

@responses.activate
def test_401_refresh():
    responses.post("https://api.test.com/auth/login", json={"access_token": "new_tok"})
    responses.get("https://api.test.com/secure", status=401)
    responses.get("https://api.test.com/secure", json={"data": "ok"}, status=200)
    client = GenericIntegrationClient(
        base_url="https://api.test.com",
        auth_method="bearer_user_pass",
        auth_config={"username": "u", "password": "p"}
    )
    result = client.get("/secure")
    assert result == {"data": "ok"}
