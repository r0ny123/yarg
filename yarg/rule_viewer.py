import ida_kernwin as kw

from PySide6 import QtGui, QtWidgets


_open_viewers = []
_next_viewer_id = 1


class YaraRuleViewer(kw.PluginForm):
    def __init__(self, rule_text: str):
        super().__init__()
        self._rule_text = rule_text
        self._parent = None

    def OnCreate(self, form):
        self._parent = self.FormToPyQtWidget(form)
        if self._parent is None:
            return
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        editor = QtWidgets.QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(self._rule_text)
        editor.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        editor.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        layout.addWidget(editor)
        self._parent.setLayout(layout)

    def OnClose(self, form):
        try:
            _open_viewers.remove(self)
        except ValueError:
            pass
        self._parent = None


def close_all_viewers() -> None:
    for viewer in list(_open_viewers):
        try:
            viewer.Close()
        except Exception:
            pass
    _open_viewers.clear()


def show_yara_rule(title: str, rule_text: str) -> None:
    title = _next_viewer_title(title)
    viewer = YaraRuleViewer(rule_text)
    _open_viewers.append(viewer)
    viewer.Show(title, kw.PluginForm.WOPN_DP_TAB)


def _next_viewer_title(title: str) -> str:
    global _next_viewer_id
    viewer_id = _next_viewer_id
    _next_viewer_id += 1
    return f"{title} #{viewer_id}"
