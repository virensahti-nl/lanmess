import os
import tempfile

import pytest


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except Exception:
            pass


@pytest.fixture
def two_databases(db_path):
    from lanmess_files.database import Database

    path_a = db_path + ".a"
    path_b = db_path + ".b"
    db_a = Database(path_a)
    db_b = Database(path_b)
    yield db_a, db_b
    for db, p in ((db_a, path_a), (db_b, path_b)):
        try:
            db.close()
        except Exception:
            pass
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(p + suffix)
            except Exception:
                pass