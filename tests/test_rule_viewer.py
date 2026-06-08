import importlib
import sys
import types


class _PluginForm:
    WOPN_DP_TAB = 0x20
    WOPN_RESTORE = 0x04
    WOPN_PERSIST = 0x40

    def Show(self, caption, options=0):
        self.shown_caption = caption
        self.shown_options = options


def _load_rule_viewer(monkeypatch):
    ida_kernwin = types.ModuleType("ida_kernwin")
    pyside6 = types.ModuleType("PySide6")
    qtgui = types.ModuleType("PySide6.QtGui")
    qtwidgets = types.ModuleType("PySide6.QtWidgets")

    ida_kernwin.PluginForm = _PluginForm
    qtgui.QFontDatabase = types.SimpleNamespace(FixedFont=0, systemFont=lambda font: font)
    qtwidgets.QPlainTextEdit = types.SimpleNamespace(NoWrap=0)

    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)
    monkeypatch.setitem(sys.modules, "PySide6", pyside6)
    monkeypatch.setitem(sys.modules, "PySide6.QtGui", qtgui)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", qtwidgets)
    sys.modules.pop("yarg.rule_viewer", None)
    return importlib.import_module("yarg.rule_viewer")


def test_yara_rule_viewer_uses_unique_non_persistent_tabs(monkeypatch):
    rule_viewer = _load_rule_viewer(monkeypatch)

    rule_viewer.show_yara_rule("YarG instruction 0000000140001000", "rule one {}")
    rule_viewer.show_yara_rule("YarG instruction 0000000140001000", "rule two {}")

    first, second = rule_viewer._open_viewers
    assert first.shown_caption == "YarG instruction 0000000140001000 #1"
    assert second.shown_caption == "YarG instruction 0000000140001000 #2"
    assert first.shown_options == _PluginForm.WOPN_DP_TAB
    assert second.shown_options == _PluginForm.WOPN_DP_TAB
    assert not first.shown_options & _PluginForm.WOPN_RESTORE
    assert not first.shown_options & _PluginForm.WOPN_PERSIST
