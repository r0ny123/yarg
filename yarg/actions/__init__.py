from dataclasses import dataclass
from typing import Optional, Type

import ida_kernwin as kw

from .create_from_function import CreatePatternFromFunctionHandler
from .create_from_selection import CreatePatternFromSelectedCodeHandler
from .create_from_single_basic_block import CreatePatternFromSelectedBasicBlockHandler
from .create_from_single_instr import CreatePatternFromSelectedInstructionHandler


POPUP_PATH = "YarG for Yara/"
ACTION_PREFIX = "YargForYara:"


@dataclass(frozen=True)
class ActionSpec:
    handler: Type[kw.action_handler_t]
    text: str
    shortcut: Optional[str] = None
    tooltip: Optional[str] = None
    icon_path: Optional[str] = None


DEFAULT_ACTIONS = (
    ActionSpec(CreatePatternFromSelectedCodeHandler, "Create YARA rule from selected range", "Ctrl+Alt+R"),
    ActionSpec(CreatePatternFromFunctionHandler, "Create YARA rule from selected function", "Ctrl+Alt+F"),
    ActionSpec(CreatePatternFromSelectedInstructionHandler, "Create YARA rule from selected instruction", "Ctrl+Alt+I"),
    ActionSpec(CreatePatternFromSelectedBasicBlockHandler, "Create YARA rule from selected basic block", "Ctrl+Alt+B"),
)


class Hooks(kw.UI_Hooks):
    def __init__(self, actions_manager):
        super().__init__()
        self._actions_manager = actions_manager

    def populating_widget_popup(self, widget, popup_handle, ctx=None):
        if kw.get_widget_type(widget) not in (kw.BWN_DISASM, kw.BWN_DISASM_ARROWS):
            return

        for action_desc in self._actions_manager.actions:
            kw.attach_action_to_popup(widget, popup_handle, action_desc.name, POPUP_PATH)


class ActionsManager:
    def __init__(self):
        self._actions: list[kw.action_desc_t] = []
        self._action_names: list[str] = []
        self._handlers: list[kw.action_handler_t] = []

    @property
    def actions(self) -> tuple[kw.action_desc_t, ...]:
        return tuple(self._actions)

    def register_defaults(self) -> bool:
        for spec in DEFAULT_ACTIONS:
            if not self.register(spec):
                self.unregister_all()
                return False
        return True

    def register(self, spec: ActionSpec) -> bool:
        icon = -1
        if spec.icon_path:
            icon = kw.load_custom_icon(spec.icon_path)
        action_name = self.action_name(spec)
        kw.unregister_action(action_name)
        handler = spec.handler()
        action_desc = kw.action_desc_t(
            action_name,
            spec.text,
            handler,
            spec.shortcut,
            spec.tooltip,
            icon,
        )
        if not kw.register_action(action_desc):
            return False
        self._actions.append(action_desc)
        self._action_names.append(action_name)
        self._handlers.append(handler)
        return True

    def unregister_all(self) -> None:
        for action_name in reversed(self._action_names):
            kw.unregister_action(action_name)
        self._actions.clear()
        self._action_names.clear()
        self._handlers.clear()

    @staticmethod
    def action_name(spec: ActionSpec) -> str:
        return f"{ACTION_PREFIX}{spec.handler.__name__}"
