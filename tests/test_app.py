"""Minimal pytest suite so the CI 'build & test' stage has something to run."""
import os
import tempfile

import pytest

import app as myapp


@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    myapp.DB_PATH = path
    myapp.init_db()
    myapp.app.config["TESTING"] = True
    with myapp.app.test_client() as c:
        yield c
    os.unlink(path)


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_create_and_list_task(client):
    resp = client.post("/tasks", json={"title": "buy milk", "owner": "karim"})
    assert resp.status_code == 201
    created = resp.get_json()
    assert created["title"] == "buy milk"

    resp = client.get("/tasks?owner=karim")
    assert resp.status_code == 200
    titles = [t["title"] for t in resp.get_json()]
    assert "buy milk" in titles


def test_etag_is_deterministic(client):
    a = client.get("/tasks/1/etag").get_json()["etag"]
    b = client.get("/tasks/1/etag").get_json()["etag"]
    assert a == b
