from dataclasses import dataclass


from ..utils import SettingsDialog, TEMPLATE_SYMBOL

from .modrm import ModRm
from .sib import Sib


@dataclass
class Displacement:
    disp: int
    offset: int
    size: int
    data: bytes

    modrm: ModRm | None
    sib: Sib | None

    @classmethod
    def from_instr(cls, instr, modrm: ModRm | None, sib: Sib | None) -> "Displacement":
        # Clamp size to the bytes actually present rather than trusting instr.disp_size,
        # so a bogus size reported by the disassembler cannot emit a runaway wildcard run.
        data = instr.bytes[instr.disp_offset : instr.disp_offset + instr.disp_size]
        return cls(disp=instr.disp, modrm=modrm, sib=sib, offset=instr.disp_offset, size=len(data), data=data)

    def print(self):
        print(f"Disp: {self.disp: 08X}")
        print(f"Disp off: {self.offset: 02X}")
        print(f"Disp size: {self.size: 02X}")

    def parameterize_address(self, settings: SettingsDialog):
        if settings.address_parameterization_mode == 0:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size

        if settings.address_parameterization_mode == 1:
            if self.size < 1:
                return ""
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 1) + f"{self.data[-1]:02X}"

        if settings.address_parameterization_mode == 2:
            if self.size < 2:
                return f"{self.data[-1]:02X}" if self.size == 1 else ""
            return (
                f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 2)
                + f"{self.data[-2]:02X}"
                + f"{self.data[-1]:02X}"
            )

    def parameterize_offset(self, settings):
        if settings.offset_parameterization_mode == 0:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size

        if settings.offset_parameterization_mode == 1:
            if self.size < 1:
                return ""
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 1) + f"{self.data[-1]:02X}"

        if settings.offset_parameterization_mode == 2:
            if self.size < 2:
                return f"{self.data[-1]:02X}" if self.size == 1 else ""
            return (
                f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 2)
                + f"{self.data[-2]:02X}"
                + f"{self.data[-1]:02X}"
            )

    def parameterize_default(self, settings: SettingsDialog):
        return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size
