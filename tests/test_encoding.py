# ruff: noqa: E402
import sys
import types
from unittest.mock import MagicMock

# Mock PySide6
pyside6 = types.ModuleType("PySide6")
sys.modules["PySide6"] = pyside6
sys.modules["PySide6.QtCore"] = types.ModuleType("PySide6.QtCore")
sys.modules["PySide6.QtGui"] = types.ModuleType("PySide6.QtGui")
sys.modules["PySide6.QtWidgets"] = types.ModuleType("PySide6.QtWidgets")

# Mock IDA modules
sys.modules["ida_ida"] = MagicMock()
sys.modules["ida_kernwin"] = MagicMock()

# Now import the target modules and capstone constants
from capstone.x86_const import X86_REG_RSP, X86_REG_RAX, X86_OP_MEM, X86_REG_EAX, X86_REG_ECX, X86_OP_REG, X86_OP_IMM
from yarg.encoding import Sib, Displacement
from yarg.locator import OperandLocator, OPERAND_SIB
from yarg.utils import is_gp_reg, SettingsDialog


def test_is_gp_reg():
    # 0 is X86_REG_INVALID (which is 0), should be False
    assert is_gp_reg(0) is False
    # stack regs should be False
    assert is_gp_reg(X86_REG_RSP) is False
    # other regs should be True
    assert is_gp_reg(X86_REG_RAX) is True


def test_sib_decoding_base_13_rex_b():
    # SIB base R13 / REX.B decoding logic: base_id in (5, 13)
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=1)  # base_id = 13
    assert sib.base_id == 13
    assert sib.is_mem_without_base_reg() is True
    assert sib.is_mem_with_only_index_disp_32() is True


def test_locator_resolves_sib_register_size():
    class FakeMem:
        def __init__(self, base, index):
            self.base = base
            self.index = index

    class FakeOperand:
        def __init__(self, type_, base, index):
            self.type = type_
            self.mem = FakeMem(base, index)

    class FakeInstr:
        def __init__(self, operands):
            self.operands = operands
            self.address = 0x401000
            self.rex = 0

        def reg_name(self, r):
            return f"reg_{r}"

    modrm = MagicMock()
    modrm.is_mem_with_sib.return_value = True
    # base=5, base_ext=0 -> base_id=5 (EBP/EBP/R13)
    # index=1, index_ext=0 -> index_id=1 (ECX/RCX)
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=0)
    disp = MagicMock()

    # operand uses 32-bit base EAX
    op = FakeOperand(X86_OP_MEM, X86_REG_EAX, X86_REG_ECX)
    instr = FakeInstr([op])

    locator = OperandLocator(instr, modrm, sib, disp)
    assert locator.locate(OPERAND_SIB) is op


def test_defensive_imm_and_disp_parameterization():
    settings = SettingsDialog()
    settings.address_parameterization_mode = 2
    settings.offset_parameterization_mode = 2

    # Displacement with size 1
    disp = Displacement(disp=5, offset=0, size=1, data=b"\x05", modrm=None, sib=None)
    assert disp.parameterize_address(settings) == "05"
    assert disp.parameterize_offset(settings) == "05"

    # Displacement with size 4
    disp4 = Displacement(disp=5, offset=0, size=4, data=b"\x01\x02\x03\x04", modrm=None, sib=None)
    assert disp4.parameterize_address(settings) == "????0304"


def test_locator_does_not_crash_on_non_mem_operands():
    class FakeOperand:
        def __init__(self, type_, reg=0, imm=0):
            self.type = type_
            self.reg = reg
            self.imm = imm

    class FakeInstr:
        def __init__(self, operands):
            self.operands = operands
            self.address = 0x401000
            self.rex = 0

        def reg_name(self, r):
            return f"reg_{r}"

    modrm = MagicMock()
    modrm.is_mem_with_sib.return_value = True
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=0)
    disp = MagicMock()

    # Non-memory operands (Register and Immediate)
    op1 = FakeOperand(X86_OP_REG, reg=X86_REG_RAX)
    op2 = FakeOperand(X86_OP_IMM, imm=0x1234)
    instr = FakeInstr([op1, op2])

    # This should run without AttributeError or ctypes reinterpretation crash
    locator = OperandLocator(instr, modrm, sib, disp)
    assert locator.locate(OPERAND_SIB) is None
