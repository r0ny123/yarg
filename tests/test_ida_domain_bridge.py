from yarg.ida_domain_bridge import has_xrefs_to


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
