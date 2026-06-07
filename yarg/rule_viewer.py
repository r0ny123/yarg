import ida_kernwin as kw

from PySide6 import QtGui, QtWidgets


_open_viewers = []


class YaraRuleViewer(kw.PluginForm):
    def __init__(self, rule_text: str):
        super().__init__()
        self._rule_text = rule_text
        self._parent = None

    def OnCreate(self, form):
        self._parent = self.FormToPyQtWidget(form)
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


def show_yara_rule(title: str, rule_text: str) -> None:
    viewer = YaraRuleViewer(rule_text)
    _open_viewers.append(viewer)
    viewer.Show(title, kw.PluginForm.WOPN_DP_TAB | kw.PluginForm.WOPN_RESTORE | kw.PluginForm.WOPN_PERSIST)
