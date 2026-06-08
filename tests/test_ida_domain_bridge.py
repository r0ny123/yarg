from yarg import ida_domain_bridge
from yarg.ida_domain_bridge import current_database, has_xrefs_to


class FakeXrefs:
    def __init__(self, values=(), raises=False):
        self.values = values
        self.raises = raises
        self.called_with = None

    def to_ea(self, ea):
        self.called_with = ea
        if self.raises:
            raise ValueError("invalid ea")
        yield from self.values


class LegacyFakeXrefs:
    def __init__(self, values=()):
        self.values = values
        self.called_with = None

    def to(self, ea):
        self.called_with = ea
        yield from self.values


class FakeDb:
    def __init__(self, xrefs):
        self.xrefs = xrefs


class FakeDatabaseHandle:
    def __init__(self):
        self.closed = False
        self.unhooked = False

    def close(self):
        self.closed = True

    def unhook(self):
        self.unhooked = True


class FakeDatabaseFactory:
    def __init__(self, db):
        self.db = db

    def open(self):
        return self.db


def test_has_xrefs_to_uses_ida_domain_to_ea_api():
    xrefs = FakeXrefs(values=[object()])

    assert has_xrefs_to(FakeDb(xrefs), 0x401000) is True
    assert xrefs.called_with == 0x401000


def test_has_xrefs_to_keeps_legacy_to_fallback():
    xrefs = LegacyFakeXrefs(values=[object()])

    assert has_xrefs_to(FakeDb(xrefs), 0x401000) is True
    assert xrefs.called_with == 0x401000


def test_has_xrefs_to_returns_false_for_invalid_or_missing_api():
    assert has_xrefs_to(None, 0x401000) is False
    assert has_xrefs_to(FakeDb(object()), 0x401000) is False
    assert has_xrefs_to(FakeDb(FakeXrefs(raises=True)), 0x401000) is False


def test_current_database_unhooks_in_ida_gui_mode(monkeypatch):
    db = FakeDatabaseHandle()
    monkeypatch.setattr(ida_domain_bridge, "Database", FakeDatabaseFactory(db))
    monkeypatch.setattr(ida_domain_bridge, "_is_ida_library_mode", lambda: False)

    with current_database() as opened:
        assert opened is db

    assert db.closed is False
    assert db.unhooked is True


def test_current_database_closes_in_ida_library_mode(monkeypatch):
    db = FakeDatabaseHandle()
    monkeypatch.setattr(ida_domain_bridge, "Database", FakeDatabaseFactory(db))
    monkeypatch.setattr(ida_domain_bridge, "_is_ida_library_mode", lambda: True)

    with current_database() as opened:
        assert opened is db

    assert db.closed is True
    assert db.unhooked is False
