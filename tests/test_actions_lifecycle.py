import importlib
import sys
import types


class _ActionHandler:
    pass


class _ActionDesc:
    def __init__(self, name, label, handler, shortcut=None, tooltip=None, icon=-1):
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.icon = icon


class _UIHooks:
    pass


class _PluginForm:
    pass


class _FakeKernwin(types.ModuleType):
    def __init__(self, fail_names=()):
        super().__init__("ida_kernwin")
        self.action_handler_t = _ActionHandler
        self.action_desc_t = _ActionDesc
        self.PluginForm = _PluginForm
        self.UI_Hooks = _UIHooks
        self.BWN_DISASM = 1
        self.BWN_DISASM_ARROWS = 2
        self.AST_ENABLE_FOR_WIDGET = 1
        self.AST_DISABLE_FOR_WIDGET = 0
        self.registered = set()
        self.unregistered = []
        self.fail_names = set(fail_names)

    def register_action(self, action_desc):
        if action_desc.name in self.fail_names or action_desc.name in self.registered:
            return False
        self.registered.add(action_desc.name)
        return True

    def unregister_action(self, name):
        self.unregistered.append(name)
        if name not in self.registered:
            return False
        self.registered.remove(name)
        return True

    def load_custom_icon(self, icon_path):
        return 1


def _load_actions_module(monkeypatch, kw):
    monkeypatch.setitem(sys.modules, "ida_kernwin", kw)
    monkeypatch.setitem(sys.modules, "ida_bytes", types.ModuleType("ida_bytes"))
    monkeypatch.setitem(sys.modules, "ida_ida", types.ModuleType("ida_ida"))
    monkeypatch.setitem(sys.modules, "ida_idaapi", types.SimpleNamespace(BADADDR=-1))

    pyside6 = types.ModuleType("PySide6")
    monkeypatch.setitem(sys.modules, "PySide6", pyside6)
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", types.ModuleType("PySide6.QtCore"))
    monkeypatch.setitem(sys.modules, "PySide6.QtGui", types.ModuleType("PySide6.QtGui"))
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", types.ModuleType("PySide6.QtWidgets"))

    for name in list(sys.modules):
        if name == "yarg.actions" or name.startswith("yarg.actions."):
            sys.modules.pop(name)
    return importlib.import_module("yarg.actions")


def test_actions_manager_unregisters_stale_action_names_before_registering(monkeypatch):
    kw = _FakeKernwin()
    actions = _load_actions_module(monkeypatch, kw)
    stale_name = actions.ActionsManager.action_name(actions.DEFAULT_ACTIONS[0])
    kw.registered.add(stale_name)

    manager = actions.ActionsManager()

    assert manager.register_defaults() is True
    assert stale_name in kw.unregistered
    assert kw.registered == {actions.ActionsManager.action_name(spec) for spec in actions.DEFAULT_ACTIONS}


def test_actions_manager_rolls_back_partial_registration_failure(monkeypatch):
    kw = _FakeKernwin()
    actions = _load_actions_module(monkeypatch, kw)
    failing_name = actions.ActionsManager.action_name(actions.DEFAULT_ACTIONS[1])
    kw.fail_names.add(failing_name)

    manager = actions.ActionsManager()

    assert manager.register_defaults() is False
    assert kw.registered == set()
    assert actions.ActionsManager.action_name(actions.DEFAULT_ACTIONS[0]) in kw.unregistered
