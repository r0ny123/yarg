import ida_bytes
import ida_kernwin as kw

from capstone import *

from ..builder import create_pattern_from_code
from ..ida_domain_bridge import current_database
from ..rule_viewer import show_yara_rule
from ..utils import VAR_NAME, SettingsDialog, __ver_major__, __ver_minor__, get_bitness, get_selected_range
from ..yara_output import YaraOutputError, build_code_rule


class CreatePatternFromSelectedCodeHandler(kw.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        start, end = get_selected_range()
        if start is None or end is None:
            kw.warning("[YarG] Selected range is invalid")
            return 0

        code = ida_bytes.get_bytes(start, end - start)
        if not code:
            kw.warning(f"[YarG] Selected range read failed (S:{hex(start)} ; E:{hex(end)})")
            return 0

        bitness = get_bitness()
        if bitness == 16:
            kw.warning("[YarG] 16-bit mode is unsupported")
            return 0

        md = Cs(CS_ARCH_X86, CS_MODE_32 if bitness == 32 else CS_MODE_64)
        md.detail = True
        settings = SettingsDialog(version=f"{__ver_major__}.{__ver_minor__}")
        settings.Compile()
        settings.set_default_check_box_values()
        if not settings.Execute():
            return 0

        with current_database() as db:
            result = create_pattern_from_code(md, code, start, settings, db=db)

        pattern = result.pattern
        if settings.cStripWildCards.checked:
            while pattern.endswith("??"):
                pattern = pattern[:-2]

        try:
            yar_rule = build_code_rule(start, pattern, result.annotations, bitness, VAR_NAME, "range", rule_end_ea=end)
        except YaraOutputError as exc:
            kw.warning(f"[YarG] {exc}")
            return 0

        show_yara_rule(f"YarG range {start:0{bitness // 4}X}-{end:0{bitness // 4}X}", yar_rule)
        return 1

    def update(self, ctx):
        if ctx.widget_type in (kw.BWN_DISASM, kw.BWN_DISASM_ARROWS):
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
