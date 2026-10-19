"""Database pool reliability tests (V19)."""

from __future__ import annotations

import threading

from sqlalchemy import text

from backend.app.infrastructure.db import get_session_factory, init_db


def test_session_cleanup_after_exception(tmp_path):
    db_url = f"sqlite:///{tmp_path}/db.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    session = factory()
    try:
        session.execute(text("SELECT 1"))
        raise RuntimeError("boom")
    except RuntimeError:
        pass
    finally:
        session.close()
    # New session works
    s2 = factory()
    assert s2.execute(text("SELECT 1")).scalar() == 1
    s2.close()


def test_concurrent_sessions(tmp_path):
    db_url = f"sqlite:///{tmp_path}/db2.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    results = []

    def worker():
        s = factory()
        try:
            results.append(s.execute(text("SELECT 1")).scalar())
        finally:
            s.close()

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == 1 for r in results)
