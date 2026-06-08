import importlib

import ida_idaapi
import ida_kernwin as kw

from yarg.version import __ver_major__, __ver_minor__


MIN_IDA_SDK_VERSION = 930
YARG_CLEANUP_ATTR = "_yarg_for_yara_cleanup"


class YaraBuilder(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    help = f"YarG for Yara v{__ver_major__}.{__ver_minor__}. Create YARA rules/patterns from code"
    wanted_name = "YarG for Yara"
    wanted_hotkey = ""
    comment = ""

    def __init__(self):
        super().__init__()
        self._hooks = None
        self._actions_manager = None
        self._cleanup_handle = None

    def init(self):
        ida_sdk_version = getattr(ida_idaapi, "IDA_SDK_VERSION", 0)
        if ida_sdk_version and ida_sdk_version < MIN_IDA_SDK_VERSION:
            kw.warning("[YarG] IDA Pro 9.3 or newer is required")
            return ida_idaapi.PLUGIN_SKIP

        self._cleanup_previous_instance()

        try:
            importlib.import_module("capstone")
            importlib.import_module("yara_x")
            importlib.import_module("yarg.ida_domain_bridge")
            from yarg.actions import ActionsManager, Hooks
        except Exception as exc:
            kw.warning(f"[YarG] Plugin dependencies are not available: {exc}")
            return ida_idaapi.PLUGIN_SKIP

        self._actions_manager = ActionsManager()
        if not self._actions_manager.register_defaults():
            kw.warning("[YarG] Failed to register one or more actions")
            self._actions_manager.unregister_all()
            self._actions_manager = None
            return ida_idaapi.PLUGIN_SKIP

        self._hooks = Hooks(self._actions_manager)
        if not self._hooks.hook():
            kw.warning("[YarG] Failed to install UI hooks")
            self._actions_manager.unregister_all()
            self._actions_manager = None
            self._hooks = None
            return ida_idaapi.PLUGIN_SKIP

        self._install_cleanup_handle()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self._cleanup()

    def _install_cleanup_handle(self):
        self._cleanup_handle = self._cleanup
        setattr(kw, YARG_CLEANUP_ATTR, self._cleanup_handle)

    def _cleanup_previous_instance(self):
        previous_cleanup = getattr(kw, YARG_CLEANUP_ATTR, None)
        if previous_cleanup is None:
            return
        try:
            previous_cleanup()
        except Exception:
            pass
        if getattr(kw, YARG_CLEANUP_ATTR, None) is previous_cleanup:
            delattr(kw, YARG_CLEANUP_ATTR)

    def _cleanup(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        if self._actions_manager is not None:
            self._actions_manager.unregister_all()
            self._actions_manager = None
        try:
            from yarg.rule_viewer import close_all_viewers

            close_all_viewers()
        except Exception:
            pass
        if getattr(kw, YARG_CLEANUP_ATTR, None) is self._cleanup_handle:
            delattr(kw, YARG_CLEANUP_ATTR)
        self._cleanup_handle = None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return YaraBuilder()
