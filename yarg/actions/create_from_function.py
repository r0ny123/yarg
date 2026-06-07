import ida_bytes
import ida_kernwin as kw

from capstone import *

from ..builder import create_pattern_from_code
from ..ida_domain_bridge import current_database, get_function_at, iter_basic_blocks
from ..rule_viewer import show_yara_rule
from ..utils import VAR_NAME, SettingsDialog, __ver_major__, __ver_minor__, get_bitness
from ..yara_output import YaraOutputError, build_function_rule


class CreatePatternFromFunctionHandler(kw.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        ea = kw.get_screen_ea()

        with current_database() as db:
            func = get_function_at(db, ea)
            if not func:
                kw.warning("[YarG] Selected address does not belong to a function")
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

            block_patterns = []
            for block in iter_basic_blocks(db, func):
                code = ida_bytes.get_bytes(block.start_ea, block.end_ea - block.start_ea)
                if not code:
                    kw.warning(f"[YarG] Basic block read failed (S:{hex(block.start_ea)} ; E:{hex(block.end_ea)})")
                    return 0

                result = create_pattern_from_code(md, code, block.start_ea, settings, db=db)
                pattern = result.pattern
                if settings.cStripWildCards.checked:
                    while pattern.endswith("??"):
                        pattern = pattern[:-2]
                block_patterns.append((block.start_ea, pattern, result.annotations))

        try:
            yar_rule = build_function_rule(ea, block_patterns, bitness, VAR_NAME)
        except YaraOutputError as exc:
            kw.warning(f"[YarG] {exc}")
            return 0

        show_yara_rule("Created YARA rule", yar_rule)
        return 0

    def update(self, ctx):
        if ctx.widget_type == kw.BWN_DISASM:
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
