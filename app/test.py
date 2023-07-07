import pytest
from starlette.testclient import TestClient
from main import app, create_tables_if_not_exist


@pytest.fixture(scope="module")
def test_client():
    create_tables_if_not_exist()
    with TestClient(app) as client:
        yield client


def test_register(test_client):
    response = test_client.post("/register", json={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}


def test_register_invalid_email(test_client):
    response = test_client.post("/register", json={"username": "invalidemail", "password": "testpassword"})
    assert response.status_code == 400


def test_login(test_client):
    response = test_client.post("/token", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_create_message(test_client):
    response = test_client.post("/create_message", json={"text": "Hello world!", "owner": "testuser"})
    assert response.status_code == 200
    assert response.json() == {"message": "Message created successfully"}


def test_get_messages(test_client):
    response = test_client.get("/messages")
    assert response.status_code == 200
    assert "messages" in response.json()


def test_delete_message(test_client):
    response = test_client.delete("/messages/1")
    assert response.status_code == 200
    assert response.json() == {"message": "Message deleted successfully"}


def test_like_message(test_client):
    response = test_client.post("/messages/1/like", json={"user_id": 1, "message_id": 1})
    assert response.status_code == 400


def test_dislike_message(test_client):
    response = test_client.delete("/messages/1/like", json={"user_id": 1, "message_id": 1})
    assert response.status_code == 400


def test_docs(test_client):
    response = test_client.get("/docs")
    assert response.status_code == 200
    assert "Swagger UI" in response.json()
    assert "ReDoc" in response.json()


def test_openapi(test_client):
    response = test_client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json() == app.openapi()


if __name__ == "__main__":
    pytest.main(["-v"])