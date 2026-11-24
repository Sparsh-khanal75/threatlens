from datetime import datetime, timezone

import pytest

from threatlens.core import Cache, Config, Http

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


class FakeResolver:
    """In-memory DNS: {(name, rtype): [answers]}."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None):
        self.records = records or {}

    async def query(self, name: str, rtype: str) -> list[str]:
        return list(self.records.get((name.lower(), rtype), []))

    async def exists(self, name: str) -> bool:
        return any(self.records.get((name, t)) for t in ("A", "NS", "MX"))


@pytest.fixture
def cfg():
    return Config(virustotal_key="vt", abuseipdb_key="ab", abusech_key="ac", cache_path="", timeout=5)


@pytest.fixture
async def http(cfg):
    async with Http(cfg, Cache(None, 0)) as h:
        yield h
