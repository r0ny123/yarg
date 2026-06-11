from binascii import hexlify

from .ida_domain_bridge import has_xrefs_to
from .encoding import ModRm, Sib, Displacement
from .locator import *
from .utils import SettingsDialog, is_gp_reg, is_stack_reg, TEMPLATE_SYMBOL, get_bitness, dbg_print, __debugmode__


class OperandParameterizer:
    def __init__(self, instr, db=None):
        self._instr = instr
        self._db = db

        if __debugmode__:
            c = -1
            for operand in instr.operands:
                c += 1
                if operand.type == X86_OP_REG:
                    dbg_print("\t\toperands[%u].type: REG = %s" % (c, instr.reg_name(operand.reg)))
                if operand.type == X86_OP_IMM:
                    dbg_print("\t\toperands[%u].type: IMM = 0x%s" % (c, hex(operand.imm)))
                if operand.type == X86_OP_MEM:
                    dbg_print("\t\toperands[%u].type: MEM" % c)
                    if operand.mem.segment != 0:
                        dbg_print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, instr.reg_name(operand.mem.segment)))
                    if operand.mem.base != 0:
                        dbg_print("\t\t\toperands[%u].mem.base: REG = %s" % (c, instr.reg_name(operand.mem.base)))
                    if operand.mem.index != 0:
                        dbg_print("\t\t\toperands[%u].mem.index: REG = %s" % (c, instr.reg_name(operand.mem.index)))
                    if operand.mem.scale != 1:
                        dbg_print("\t\t\toperands[%u].mem.scale: %u" % (c, operand.mem.scale))
                    if operand.mem.disp != 0:
                        dbg_print("\t\t\toperands[%u].mem.disp: 0x%s" % (c, hex(operand.mem.disp)))

        R = 0
        B = 0
        X = 0
        if instr.rex:
            prefix = instr.rex & 0xF

            R = (prefix & 4) >> 2
            B = prefix & 1
            X = (prefix & 2) >> 1

        self.modrm: ModRm | None = None
        self.sib: Sib | None = None
        self.disp: Displacement | None = None

        if instr.modrm_offset:
            self.modrm: ModRm = ModRm.from_instr(self._instr, R, B)
            if __debugmode__:
                self.modrm.print()

        if self.modrm and self.modrm.is_mem_with_sib():
            self.sib = Sib.from_instr(self._instr, self.modrm.mod, X, B)
            if __debugmode__:
                self.sib.print()

        if instr.disp_offset:
            self.disp = Displacement.from_instr(instr, self.modrm, self.sib)
            if __debugmode__:
                self.disp.print()

        self.locator = OperandLocator(instr, self.modrm, self.sib, self.disp)

    def parameterize_modrm_byte(self, settings: SettingsDialog) -> str:
        """
        Parameterize Mod R/M byte
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the Mod R/M byte
        """
        assert self.modrm is not None
        i = 0
        reg_op = self.locator.locate(OPERAND_MODRM_REG)

        if reg_op and is_stack_reg(reg_op.reg) and settings.cSRegistersParam.checked and reg_op.reg in settings.sp_regs:
            i = 1

        if reg_op and is_gp_reg(reg_op.reg) and settings.cGpRegistersParam.checked and reg_op.reg in settings.gp_regs:
            i = 1

        j = 0
        rm_op = self.locator.locate(OPERAND_MODRM_RM)

        if rm_op and rm_op.type == X86_OP_REG:
            if is_stack_reg(rm_op.reg) and settings.cSRegistersParam.checked and rm_op.reg in settings.sp_regs:
                j = 1

            if is_gp_reg(rm_op.reg) and settings.cGpRegistersParam.checked and rm_op.reg in settings.gp_regs:
                j = 1

        if rm_op and self.modrm.is_mem_with_rm_base_reg():
            if (
                is_stack_reg(rm_op.mem.base)
                and settings.cSRegistersParam.checked
                and rm_op.mem.base in settings.sp_regs
            ):
                j = 1

            if is_gp_reg(rm_op.mem.base) and settings.cGpRegistersParam.checked and rm_op.mem.base in settings.gp_regs:
                j = 1

        # The following code are using a special matrix (2X2) to resolve a operation applied to Mod R/M
        # You can read i and j as "We spin a value of R/M if value of j true"
        # and "We spin a value of Reg if value of i true"
        return self.modrm.parameterize(i, j, settings)

    def parameterize_sib_byte(self, settings: SettingsDialog):
        """
        Parameterize Scale/Index/Base byte
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the SIB byte
        """
        assert self.sib is not None
        sib_op = self.locator.locate(OPERAND_SIB)

        if sib_op is None:
            print(f"[!] {self._instr.address:08X}: Match operands to Sib data failed! Used default template")
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"

        j = 0
        if (
            self.sib.is_mem_with_base_reg()
            and is_stack_reg(sib_op.mem.base)
            and settings.cSRegistersParam.checked
            and sib_op.mem.base in settings.sp_regs
        ):
            j = 1

        if (
            self.sib.is_mem_with_base_reg()
            and is_gp_reg(sib_op.mem.base)
            and settings.cGpRegistersParam.checked
            and sib_op.mem.base in settings.gp_regs
        ):
            j = 1

        i = 0
        if (
            self.sib.is_mem_with_index()
            and is_stack_reg(sib_op.mem.index)
            and settings.cSRegistersParam.checked
            and sib_op.mem.index in settings.sp_regs
        ):
            i = 1

        if (
            self.sib.is_mem_with_index()
            and is_gp_reg(sib_op.mem.index)
            and settings.cGpRegistersParam.checked
            and sib_op.mem.index in settings.gp_regs
        ):
            i = 1

        # i, j means the same things as for Mod R/M
        return self.sib.parameterize(i, j, settings)

    def parameterize_disp(self, settings: SettingsDialog):
        """
        Parameterize displacement value
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the displacement value
        """
        assert self.disp is not None

        rm_op = self.locator.locate(OPERAND_MODRM_RM)

        if (
            rm_op
            and self.modrm
            and self.modrm.is_mem_with_rm_base_reg_and_disp()
            and is_gp_reg(rm_op.mem.base)
            and settings.cGpDisplacementParam.checked
        ):
            dbg_print("parameterize_disp(): rm_base_reg_and_disp + gp_reg")
            return self.disp.parameterize_default(settings)

        if (
            rm_op
            and self.modrm
            and self.modrm.is_mem_with_rm_base_reg_and_disp()
            and is_stack_reg(rm_op.mem.base)
            and settings.cSDisplacementParam.checked
        ):
            dbg_print("parameterize_disp(): rm_base_reg_and_disp + sp_reg")
            return self.disp.parameterize_default(settings)

        sib_op = self.locator.locate(OPERAND_SIB)

        if (
            sib_op
            and self.modrm
            and self.modrm.is_mem_with_sib_and_disp()
            and is_gp_reg(sib_op.mem.base)
            and settings.cGpDisplacementParam.checked
        ):
            dbg_print("parameterize_disp(): sib_and_disp + gp_reg")
            return self.disp.parameterize_default(settings)

        if (
            sib_op
            and self.modrm
            and self.modrm.is_mem_with_sib_and_disp()
            and is_stack_reg(sib_op.mem.base)
            and settings.cSDisplacementParam.checked
        ):
            dbg_print("parameterize_disp(): sib_and_disp + sp_reg")
            return self.disp.parameterize_default(settings)

        disp_op = self.locator.locate(OPERAND_DISP)

        if disp_op and not self.modrm and not self.sib:
            dbg_print("parameterize_disp(): only_disp (address)")
            return self.disp.parameterize_address(settings)

        if self.modrm and self.modrm.is_mem_rip_rel():
            if get_bitness() == 32:
                dbg_print("parameterize_disp(): only_disp_rip_rel (address)")
                return self.disp.parameterize_address(settings)
            else:
                dbg_print("parameterize_disp(): only_disp_rip_rel (offset)")
                return self.disp.parameterize_offset(settings)

        if sib_op and self.sib and self.sib.is_mem_without_base_reg():
            dbg_print("parameterize_disp(): sib_without_base (address)")
            return self.disp.parameterize_address(settings)

        # Use the clamped displacement bytes captured by Displacement rather than the raw
        # instr.disp_size, so a bogus size reported by the disassembler cannot leak in here.
        return self.disp.data.hex().upper()

    def _disp_template_for(self, disp: "Displacement", modrm: "ModRm", sib: "Sib | None", settings: SettingsDialog):
        """Render the displacement template for a hypothetical (flipped-mod) memory operand.

        Mirrors the stack/GP-base branches of ``parameterize_disp`` for a synthetic
        ``Displacement``/``ModRm`` pair, so the alternate disp8<->disp32 encoding respects the
        very same wildcarding the native form got. Only the stack/GP base-register cases are
        reachable here (the caller gates on a stack base), so address/RIP/no-base paths are
        intentionally not reproduced.
        """
        rm_op = self.locator.locate(OPERAND_MODRM_RM)
        sib_op = self.locator.locate(OPERAND_SIB)

        if rm_op and modrm.is_mem_with_rm_base_reg_and_disp() and is_gp_reg(rm_op.mem.base):
            if settings.cGpDisplacementParam.checked:
                return disp.parameterize_default(settings)
        if rm_op and modrm.is_mem_with_rm_base_reg_and_disp() and is_stack_reg(rm_op.mem.base):
            if settings.cSDisplacementParam.checked:
                return disp.parameterize_default(settings)
        if sib_op and modrm.is_mem_with_sib_and_disp() and is_gp_reg(sib_op.mem.base):
            if settings.cGpDisplacementParam.checked:
                return disp.parameterize_default(settings)
        if sib_op and modrm.is_mem_with_sib_and_disp() and is_stack_reg(sib_op.mem.base):
            if settings.cSDisplacementParam.checked:
                return disp.parameterize_default(settings)

        return disp.data.hex().upper()

    def stack_disp_size_variant(self, native_modrm_t: str, sib_t: str, native_disp_t: str, settings: SettingsDialog):
        """Build the alternate disp8<->disp32 encoding tail for a stack-frame memory operand.

        A compiler may encode the same frame access with a 1-byte (disp8, ModRM mod=01) or
        4-byte (disp32, ModRM mod=10) displacement. This flips the ModRM mod bits *and* changes
        length, so it is emitted as a whole-instruction-tail alternation, not a field wildcard.

        Returns the alternate tail string ``modrm+sib+disp`` (same prefix/REX/opcode/reg bits,
        flipped mod, unchanged SIB, resized displacement), or ``None`` when the instruction is
        not a transformable stack-frame access (no displacement, non-stack base, or a disp32
        whose signed value does not fit in an int8 so no disp8 alternate exists).
        """
        if self.modrm is None or self.disp is None:
            return None
        if self.modrm.mod not in (1, 2):
            return None

        # Identify a stack base, either a direct rm base (rbp/ebp) or a SIB base (rsp/esp/rbp/ebp).
        rm_op = self.locator.locate(OPERAND_MODRM_RM)
        sib_op = self.locator.locate(OPERAND_SIB)

        is_stack_rm_base = (
            rm_op is not None
            and self.modrm.is_mem_with_rm_base_reg_and_disp()
            and is_stack_reg(rm_op.mem.base)
        )
        is_stack_sib_base = (
            sib_op is not None
            and self.modrm.is_mem_with_sib_and_disp()
            and self.sib is not None
            and self.sib.is_mem_with_base_reg()
            and is_stack_reg(sib_op.mem.base)
        )
        if not (is_stack_rm_base or is_stack_sib_base):
            return None

        if self.modrm.mod == 1:
            # disp8 source -> sign-extend to a 4-byte disp32 alternate (mod=10). Always valid.
            new_mod = 2
            value = self.disp.disp
            new_data = (value & 0xFFFFFFFF).to_bytes(4, "little")
        else:
            # disp32 source -> emit a disp8 alternate (mod=01) only if it fits in a signed byte.
            if not (-128 <= self.disp.disp <= 127):
                return None
            new_mod = 1
            value = self.disp.disp
            new_data = (value & 0xFF).to_bytes(1, "little")

        alt_modrm = ModRm(
            mod=new_mod,
            reg=self.modrm.reg,
            rm=self.modrm.rm,
            reg_ext=self.modrm.reg_ext,
            rm_ext=self.modrm.rm_ext,
        )
        alt_sib = None
        if self.sib is not None:
            alt_sib = Sib(
                mod=new_mod,
                scale=self.sib.scale,
                index=self.sib.index,
                base=self.sib.base,
                index_ext=self.sib.index_ext,
                base_ext=self.sib.base_ext,
            )
        alt_disp = Displacement(
            disp=value,
            offset=self.disp.offset,
            size=len(new_data),
            data=new_data,
            modrm=alt_modrm,
            sib=alt_sib,
        )

        # Recompute the ModRM template under the flipped mod, preserving the native reg/rm
        # parameterization. parameterize_modrm_byte's i/j choice is mod-independent, so the
        # same rotation applies; only the literal mod bits differ.
        alt_op_modrm = self.modrm
        self.modrm = alt_modrm
        try:
            alt_modrm_t = self.parameterize_modrm_byte(settings)
        finally:
            self.modrm = alt_op_modrm

        alt_disp_t = self._disp_template_for(alt_disp, alt_modrm, alt_sib, settings)

        return alt_modrm_t + sib_t + alt_disp_t

    def parameterize_imm(self, settings: SettingsDialog):
        """
        Parameterize immediate value
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the immediate value
        """

        # Clamp imm_size to the bytes actually present: capstone can report a bogus
        # imm_size for some encodings (e.g. far ptr16:32 calls report sizes far larger
        # than the instruction), which would otherwise emit a runaway wildcard sequence.
        imm_offset = self._instr.imm_offset
        imm_data = self._instr.bytes[imm_offset : imm_offset + self._instr.imm_size]
        imm_size = len(imm_data)

        imm_op = self.locator.locate(OPERAND_IMM)

        if not imm_op:
            print(f"[!] {self._instr.address:08X}: Unsupported immediate usage")
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        imm = imm_op.imm

        if settings.cImmediateParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        rm_op = self.locator.locate(OPERAND_MODRM_RM)
        reg_op = self.locator.locate(OPERAND_MODRM_REG)

        if rm_op and rm_op.type == X86_OP_REG and is_stack_reg(rm_op.reg) and settings.cSImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if reg_op and is_stack_reg(reg_op.reg) and settings.cSImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if rm_op and rm_op.type == X86_OP_REG and is_gp_reg(rm_op.reg) and settings.cGpImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if reg_op and is_gp_reg(reg_op.reg) and settings.cGpImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if has_xrefs_to(self._db, imm):
            if settings.address_parameterization_mode == 0:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

            if settings.address_parameterization_mode == 1:
                if imm_size < 1:
                    return ""
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (imm_size - 1) + f"{imm_data[-1]:02X}"

            if settings.address_parameterization_mode == 2:
                if imm_size < 2:
                    return f"{imm_data[-1]:02X}" if imm_size == 1 else ""
                return (
                    f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (imm_size - 2)
                    + f"{imm_data[-2]:02X}"
                    + f"{imm_data[-1]:02X}"
                )

        return hexlify(self._instr.bytes[imm_offset : imm_offset + imm_size]).decode("utf-8").upper()
