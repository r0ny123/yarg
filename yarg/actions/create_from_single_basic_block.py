import ida_bytes
import ida_idaapi
import ida_kernwin as kw

from capstone import *

from ..builder import create_pattern_from_code
from ..ida_domain_bridge import current_database, get_function_at, iter_basic_blocks
from ..rule_viewer import show_yara_rule
from ..utils import VAR_NAME, SettingsDialog, __ver_major__, __ver_minor__, get_bitness
from ..yara_output import YaraOutputError, build_code_rule


class CreatePatternFromSelectedBasicBlockHandler(kw.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        ea = kw.get_screen_ea()
        if ea == ida_idaapi.BADADDR:
            kw.warning("[YarG] Selected instruction is invalid")
            return 0

        with current_database() as db:
            func = get_function_at(db, ea)
            if not func:
                kw.warning("[YarG] Selected address does not belong to a function")
                return 0

            bb = None
            for block in iter_basic_blocks(db, func):
                if block.start_ea <= ea < block.end_ea:
                    bb = block
                    break
            if bb is None:
                kw.warning("[YarG] Basic block resolving failed")
                return 0

            code = ida_bytes.get_bytes(bb.start_ea, bb.end_ea - bb.start_ea)
            if not code:
                kw.warning(f"[YarG] Basic block read failed (S:{hex(bb.start_ea)} ; E:{hex(bb.end_ea)})")
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

            result = create_pattern_from_code(md, code, bb.start_ea, settings, db=db)

        pattern = result.pattern
        if settings.cStripWildCards.checked:
            while pattern.endswith("??"):
                pattern = pattern[:-2]

        try:
            yar_rule = build_code_rule(bb.start_ea, pattern, result.annotations, bitness, VAR_NAME, "bb")
        except YaraOutputError as exc:
            kw.warning(f"[YarG] {exc}")
            return 0

        show_yara_rule(f"YarG basic block {bb.start_ea:0{bitness // 4}X}", yar_rule)
        return 0

    def update(self, ctx):
        if ctx.widget_type == kw.BWN_DISASM:
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
