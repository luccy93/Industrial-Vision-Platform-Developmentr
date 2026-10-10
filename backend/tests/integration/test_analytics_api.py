"""Analytics endpoint tests — summary, trends, breakdowns, export (V14)."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from backend.app.domain.common import utcnow

EPOCH = "2026-01-01T00:00:00Z"


def _seed(client: TestClient) -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "A", "camera_id": "cam-01", "source_type": "file", "source": "a.mp4"},
    )
    assert res.status_code == 201
    for index, (title, priority) in enumerate([("a", "P1"), ("b", "P2")]):
        res = client.post("/api/v1/incidents", json={"title": title, "priority": priority})
        assert res.status_code == 201
    # Backdate one incident into the window via the repository would need
    # internals; instead the window below covers "now".


def _window(days: int = 30) -> str:
    from urllib.parse import urlencode

    end = utcnow()
    start = end - timedelta(days=days)
    return urlencode({"start_at": start.isoformat(), "end_at": end.isoformat()})


def test_summary_contract(client: TestClient) -> None:
    _seed(client)
    res = client.get(f"/api/v1/analytics/summary?{_window()}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body) == {"start_at", "end_at", "generated_at", "events", "incidents", "quality", "cameras"}
    assert body["incidents"]["created_total"] == 2
    assert body["incidents"]["open_total"] == 2
    assert body["incidents"]["by_priority"] == {"P1": 1, "P2": 1}
    assert body["incidents"]["resolution"] == {
        "count": 0,
        "average_seconds": None,
        "median_seconds": None,
        "min_seconds": None,
        "max_seconds": None,
    }
    # Quality inspection outcomes are unavailable by locked decision.
    assert body["quality"]["status"] == "unavailable"
    assert "not persisted" in body["quality"]["reason"]
    assert body["cameras"]["status"] == "ok"


def test_summary_bare_path_stays_200(client: TestClient) -> None:
    res = client.get("/api/v1/analytics/summary")
    assert res.status_code == 200
    assert "generated_at" in res.json()


def test_summary_validation(client: TestClient) -> None:
    res = client.get("/api/v1/analytics/summary?start_at=2026-02-01T00:00:00Z&end_at=2026-01-01T00:00:00Z")
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_error"
    res = client.get("/api/v1/analytics/summary?start_at=nope&end_at=2026-01-02T00:00:00Z")
    assert res.status_code == 422


def test_trends_buckets(client: TestClient) -> None:
    _seed(client)
    res = client.get(f"/api/v1/analytics/trends?{_window(2)}&bucket=day&metric=incidents_created")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["metric"] == "incidents_created"
    assert body["bucket"] == "day"
    assert sum(b["count"] for b in body["buckets"]) == 2
    assert body["truncated"] is False
    # Bucket boundaries are inclusive-start ordered and aligned.
    starts = [b["bucket_start"] for b in body["buckets"]]
    assert starts == sorted(starts)
    res = client.get(f"/api/v1/analytics/trends?{_window()}&bucket=minute&metric=events")
    assert res.status_code == 422
    res = client.get(f"/api/v1/analytics/trends?{_window()}&bucket=day&metric=bogus")
    assert res.status_code == 422


def test_breakdowns(client: TestClient) -> None:
    _seed(client)
    res = client.get(f"/api/v1/analytics/breakdowns?{_window()}&dataset=incidents&group_by=priority")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["groups"] == [
        {"key": "P1", "label": "P1", "count": 1},
        {"key": "P2", "label": "P2", "count": 1},
    ]
    res = client.get(f"/api/v1/analytics/breakdowns?{_window()}&dataset=events&group_by=domain")
    assert res.status_code == 200
    assert res.json()["groups"] == []
    res = client.get(f"/api/v1/analytics/breakdowns?{_window()}&dataset=incidents&group_by=outcome")
    assert res.status_code == 422


def test_export_incidents_csv(client: TestClient) -> None:
    import csv
    import io

    _seed(client)
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=incidents")
    assert res.status_code == 200, res.text
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    assert res.content.startswith(b"\xef\xbb\xbf")
    reader = list(csv.DictReader(io.StringIO(res.content.decode("utf-8-sig"))))
    assert len(reader) == 2
    assert reader[0]["incident_number"].startswith("INC-")
    assert set(reader[0]) == {
        "incident_number",
        "title",
        "status",
        "priority",
        "severity",
        "category",
        "camera_id",
        "created_at",
        "acknowledged_at",
        "resolved_at",
        "closed_at",
        "assigned_to",
    }


def test_export_rejects_unsupported_report(client: TestClient) -> None:
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=quality")
    assert res.status_code == 422
    assert "not persisted" in res.json()["error"]["message"]
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=bogus")
    assert res.status_code == 422


def test_export_formula_injection_mitigated(client: TestClient) -> None:
    import csv
    import io

    res = client.post("/api/v1/incidents", json={"title": '=HYPERLINK("http://evil")', "priority": "P4"})
    assert res.status_code == 201
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=incidents")
    assert res.status_code == 200
    reader = list(csv.DictReader(io.StringIO(res.content.decode("utf-8-sig"))))
    titles = [row["title"] for row in reader]
    assert '\'=HYPERLINK("http://evil")' in titles


def test_export_filter_parity(client: TestClient) -> None:
    import csv
    import io

    _seed(client)
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=incidents&priority=P1")
    assert res.status_code == 200
    reader = list(csv.DictReader(io.StringIO(res.content.decode("utf-8-sig"))))
    assert len(reader) == 1
    assert reader[0]["priority"] == "P1"
    trends = client.get(
        f"/api/v1/analytics/breakdowns?{_window()}&dataset=incidents&group_by=priority"
    ).json()
    assert {g["key"]: g["count"] for g in trends["groups"]}["P1"] == 1
