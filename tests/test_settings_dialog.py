import importlib
import inspect
import sys
import types


class _Signal:
    def __init__(self):
        self._callbacks = []

    def connect(self, callback):
        self._callbacks.append(callback)

    def emit(self, *args):
        for callback in self._callbacks:
            callback(*args)


class _Widget:
    def __init__(self, *args, **kwargs):
        self._enabled = True

    def setEnabled(self, enabled):
        self._enabled = bool(enabled)


class _AbstractButton(_Widget):
    def __init__(self, label=""):
        super().__init__()
        self.label = label
        self._checked = False
        self.toggled = _Signal()

    def setChecked(self, checked):
        checked = bool(checked)
        changed = self._checked != checked
        self._checked = checked
        if changed:
            self.toggled.emit(checked)

    def isChecked(self):
        return self._checked


class _QDialog(_Widget):
    Accepted = 1
    Rejected = 0
    next_result = Accepted
    on_exec = None

    def setWindowTitle(self, title):
        self.title = title

    def setModal(self, modal):
        self.modal = modal

    def setSizeGripEnabled(self, enabled):
        self.size_grip_enabled = enabled

    def resize(self, width, height):
        self.size = (width, height)

    def setMinimumSize(self, width, height):
        self.minimum_size = (width, height)

    def exec(self):
        if self.__class__.on_exec is not None:
            self.__class__.on_exec()
        return self.__class__.next_result

    def accept(self):
        self.__class__.next_result = self.Accepted

    def reject(self):
        self.__class__.next_result = self.Rejected


class _QDialogButtonBox(_Widget):
    Ok = 1
    Cancel = 2

    def __init__(self, buttons):
        super().__init__()
        self.buttons = buttons
        self.accepted = _Signal()
        self.rejected = _Signal()


class _Layout:
    def __init__(self, *args, **kwargs):
        self.items = []

    def addWidget(self, widget, *args):
        self.items.append(widget)

    def addStretch(self, stretch):
        self.items.append(stretch)

    def setAlignment(self, alignment):
        self.alignment = alignment


class _ScrollArea(_Widget):
    def setWidgetResizable(self, resizable):
        self.resizable = resizable

    def setWidget(self, widget):
        self.widget = widget


def _load_settings_module(monkeypatch):
    pyside6 = types.ModuleType("PySide6")
    qtcore = types.ModuleType("PySide6.QtCore")
    qtwidgets = types.ModuleType("PySide6.QtWidgets")

    qtcore.Qt = types.SimpleNamespace(AlignTop=1)
    qtwidgets.QCheckBox = _AbstractButton
    qtwidgets.QDialog = _QDialog
    qtwidgets.QDialogButtonBox = _QDialogButtonBox
    qtwidgets.QGridLayout = _Layout
    qtwidgets.QGroupBox = _Widget
    qtwidgets.QRadioButton = _AbstractButton
    qtwidgets.QScrollArea = _ScrollArea
    qtwidgets.QVBoxLayout = _Layout
    qtwidgets.QWidget = _Widget

    monkeypatch.setitem(sys.modules, "PySide6", pyside6)
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", qtcore)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", qtwidgets)
    sys.modules.pop("yarg.forms", None)
    sys.modules.pop("yarg.forms.settings", None)
    return importlib.import_module("yarg.forms.settings")


def test_legacy_ida_form_change_crash_paths_are_absent(monkeypatch):
    settings_module = _load_settings_module(monkeypatch)
    source = inspect.getsource(settings_module.SettingsDialog)

    assert not hasattr(settings_module.SettingsDialog, "OnFormChange")
    assert "cFoldSameHig4hbit" not in source
    assert "fid == self.cSImmParam.checked" not in source
    assert "fid == self.cGpImmParam.checked" not in source


def test_cancelled_master_toggle_does_not_leak_into_settings(monkeypatch):
    settings_module = _load_settings_module(monkeypatch)
    dialog = settings_module.SettingsDialog()
    dialog.set_default_check_box_values()
    original_gp_regs = list(dialog.gp_regs)

    def toggle_gp_master():
        dialog._checkbox_widgets[id(dialog.cGpRegistersParam)].setChecked(False)

    _QDialog.on_exec = toggle_gp_master
    _QDialog.next_result = _QDialog.Rejected

    assert dialog.Execute() == 0
    assert dialog.cGpRegistersParam.checked is True
    assert dialog.is_gp_enabled is True
    assert dialog.gp_regs == original_gp_regs
    assert all(control.checked for control in dialog.gp_chk_regs)


def test_accepted_master_toggle_is_synced_into_settings(monkeypatch):
    settings_module = _load_settings_module(monkeypatch)
    dialog = settings_module.SettingsDialog()
    dialog.set_default_check_box_values()

    def toggle_gp_master():
        dialog._checkbox_widgets[id(dialog.cGpRegistersParam)].setChecked(False)

    _QDialog.on_exec = toggle_gp_master
    _QDialog.next_result = _QDialog.Accepted

    assert dialog.Execute() == 1
    assert dialog.cGpRegistersParam.checked is False
    assert dialog.is_gp_enabled is False
    assert dialog.gp_regs == []
    assert all(not control.checked for control in dialog.gp_chk_regs)


def test_cancelled_sp_master_toggle_does_not_leak_into_settings(monkeypatch):
    settings_module = _load_settings_module(monkeypatch)
    dialog = settings_module.SettingsDialog()
    dialog.set_default_check_box_values()
    original_sp_regs = list(dialog.sp_regs)

    def toggle_sp_master():
        dialog._checkbox_widgets[id(dialog.cSRegistersParam)].setChecked(True)

    _QDialog.on_exec = toggle_sp_master
    _QDialog.next_result = _QDialog.Rejected

    assert dialog.Execute() == 0
    assert dialog.cSRegistersParam.checked is False
    assert dialog.is_sp_enabled is False
    assert dialog.sp_regs == original_sp_regs
    assert all(not control.checked for control in dialog.sp_chk_regs)


def test_accepted_sp_master_toggle_is_synced_into_settings(monkeypatch):
    settings_module = _load_settings_module(monkeypatch)
    dialog = settings_module.SettingsDialog()
    dialog.set_default_check_box_values()

    def toggle_sp_master():
        dialog._checkbox_widgets[id(dialog.cSRegistersParam)].setChecked(True)

    _QDialog.on_exec = toggle_sp_master
    _QDialog.next_result = _QDialog.Accepted

    assert dialog.Execute() == 1
    assert dialog.cSRegistersParam.checked is True
    assert dialog.is_sp_enabled is True
    assert len(dialog.sp_regs) > 0
    assert all(control.checked for control in dialog.sp_chk_regs)
