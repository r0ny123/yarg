from dataclasses import dataclass
from typing import Optional, Type

import ida_kernwin as kw

from .create_from_function import CreatePatternFromFunctionHandler
from .create_from_selection import CreatePatternFromSelectedCodeHandler
from .create_from_single_basic_block import CreatePatternFromSelectedBasicBlockHandler
from .create_from_single_instr import CreatePatternFromSelectedInstructionHandler


POPUP_PATH = "YarG for Yara/"


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

    def populating_widget_popup(self, widget, popup, ctx):
        if kw.get_widget_type(widget) not in (kw.BWN_DISASM, kw.BWN_DISASM_ARROWS):
            return

        for action_desc in self._actions_manager.actions:
            kw.attach_action_to_popup(widget, popup, action_desc.name, POPUP_PATH)


class ActionsManager:
    def __init__(self):
        self._actions: list[kw.action_desc_t] = []

    @property
    def actions(self) -> tuple[kw.action_desc_t, ...]:
        return tuple(self._actions)

    def register_defaults(self) -> bool:
        return all(self.register(spec) for spec in DEFAULT_ACTIONS)

    def register(self, spec: ActionSpec) -> bool:
        icon = -1
        if spec.icon_path:
            icon = kw.load_custom_icon(spec.icon_path)
        action_desc = kw.action_desc_t(
            f"YargForYara:{spec.handler.__name__}",
            spec.text,
            spec.handler(),
            spec.shortcut,
            spec.tooltip,
            icon,
        )
        if not kw.register_action(action_desc):
            return False
        self._actions.append(action_desc)
        return True

    def unregister_all(self) -> None:
        for action_desc in reversed(self._actions):
            kw.unregister_action(action_desc.name)
        self._actions.clear()
