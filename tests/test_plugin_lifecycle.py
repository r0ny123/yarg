import importlib.util
import sys
import types
from pathlib import Path


class _PluginBase:
    pass


class _FakeIdaApi(types.ModuleType):
    def __init__(self):
        super().__init__("ida_idaapi")
        self.PLUGIN_FIX = 1
        self.PLUGIN_HIDE = 16
        self.PLUGIN_SKIP = -1
        self.PLUGIN_KEEP = 0
        self.IDA_SDK_VERSION = 930
        self.plugin_t = _PluginBase


class _FakeKernwin(types.ModuleType):
    def __init__(self):
        super().__init__("ida_kernwin")
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class _FakeActionsManager:
    instances = []

    def __init__(self):
        self.registered = False
        self.unregistered = False
        self.__class__.instances.append(self)

    def register_defaults(self):
        self.registered = True
        return True

    def unregister_all(self):
        self.unregistered = True


class _FakeHooks:
    instances = []

    def __init__(self, actions_manager):
        self.actions_manager = actions_manager
        self.hooked = False
        self.unhooked = False
        self.__class__.instances.append(self)

    def hook(self):
        self.hooked = True
        return True

    def unhook(self):
        self.unhooked = True


def _load_plugin_module(monkeypatch, kw):
    actions_module = types.ModuleType("yarg.actions")
    actions_module.ActionsManager = _FakeActionsManager
    actions_module.Hooks = _FakeHooks
    monkeypatch.setitem(sys.modules, "ida_idaapi", _FakeIdaApi())
    monkeypatch.setitem(sys.modules, "ida_kernwin", kw)
    monkeypatch.setitem(sys.modules, "yarg.actions", actions_module)

    spec = importlib.util.spec_from_file_location(
        "yarg_plugin_under_test",
        Path(__file__).resolve().parents[1] / "yarg.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_plugin_init_cleans_previous_local_iteration_instance(monkeypatch):
    kw = _FakeKernwin()
    previous = {"called": False}
    setattr(kw, "_yarg_for_yara_cleanup", lambda: previous.update(called=True))
    plugin_module = _load_plugin_module(monkeypatch, kw)

    plugin = plugin_module.YaraBuilder()

    assert plugin.init() == plugin_module.ida_idaapi.PLUGIN_KEEP
    assert previous["called"] is True
    assert getattr(kw, "_yarg_for_yara_cleanup") is plugin._cleanup_handle
    assert _FakeActionsManager.instances[-1].registered is True
    assert _FakeHooks.instances[-1].hooked is True

    plugin.term()

    assert _FakeActionsManager.instances[-1].unregistered is True
    assert _FakeHooks.instances[-1].unhooked is True
    assert not hasattr(kw, "_yarg_for_yara_cleanup")
