from dataclasses import dataclass

from PySide6 import QtCore, QtWidgets
from capstone.x86_const import *


@dataclass
class _CheckControl:
    checked: bool = False


class SettingsDialog:
    def __init__(self, version="0.1", extension=r"", extension_controls=None):
        self.version = version
        self.extension = extension
        self.extension_controls = extension_controls or {}
        self.address_parameterization_mode = 1
        self.offset_parameterization_mode = 1
        self.is_gp_enabled = True
        self.is_sp_enabled = False
        self.gp_regs = []
        self.sp_regs = []

        self.cGpRegistersParam = _CheckControl()
        self.cSRegistersParam = _CheckControl()
        self.cFoldSameHigh4bit = _CheckControl()
        self.cFoldSameLow4bit = _CheckControl()
        self.cStripWildCards = _CheckControl()
        self.cBranchEncodingVariants = _CheckControl()
        self.cWeightedBlockVoting = _CheckControl()
        self.cAtomGovernor = _CheckControl()
        self.cRexOperandSizeFixed = _CheckControl()
        self.cStackDispSizeVariants = _CheckControl()
        self.cAccumulatorEncodingVariants = _CheckControl()
        self.cInterInstructionGaps = _CheckControl()
        self.cTrackBasicBlockSequences = _CheckControl()
        self.cImmediateParam = _CheckControl()
        self.cGpImmParam = _CheckControl()
        self.cSImmParam = _CheckControl()
        self.cSDisplacementParam = _CheckControl()
        self.cGpDisplacementParam = _CheckControl()
        self.iAX = _CheckControl()
        self.iDX = _CheckControl()
        self.iCX = _CheckControl()
        self.iBX = _CheckControl()
        self.iSI = _CheckControl()
        self.iDI = _CheckControl()
        self.iSP = _CheckControl()
        self.iBP = _CheckControl()
        self.iR8 = _CheckControl()
        self.iR9 = _CheckControl()
        self.iR10 = _CheckControl()
        self.iR11 = _CheckControl()
        self.iR12 = _CheckControl()
        self.iR13 = _CheckControl()
        self.iR14 = _CheckControl()
        self.iR15 = _CheckControl()

        self.gp_chk_regs = [
            self.iAX,
            self.iDX,
            self.iCX,
            self.iBX,
            self.iSI,
            self.iDI,
            self.iR8,
            self.iR9,
            self.iR10,
            self.iR11,
            self.iR12,
            self.iR13,
            self.iR14,
            self.iR15,
        ]
        self.sp_chk_regs = [self.iSP, self.iBP]
        self._checkbox_widgets = {}
        self._address_buttons = []
        self._offset_buttons = []

    def Compile(self):
        return True

    def Execute(self):
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle(f"Code pattern generator for IDA. v{self.version}")
        dialog.setModal(True)
        dialog.setSizeGripEnabled(True)
        dialog.resize(920, 760)
        dialog.setMinimumSize(560, 420)

        main_layout = QtWidgets.QVBoxLayout(dialog)
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        content = QtWidgets.QWidget()
        content_layout = QtWidgets.QVBoxLayout(content)
        content_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        self._checkbox_widgets = {}
        for group in (
            self._registers_group(),
            self._radio_group(
                "Address",
                [
                    "Full address parametrisation",
                    "Parameterize first 3 bytes of address (32bit)",
                    "Parameterize first 2 bytes of address (32bit)",
                ],
                self.address_parameterization_mode,
                "_address_buttons",
            ),
            self._radio_group(
                "Code offset",
                [
                    "Full offset parametrisation",
                    "Parameterize first 3 bytes of offset",
                    "Parameterize first 2 bytes of offset",
                ],
                self.offset_parameterization_mode,
                "_offset_buttons",
            ),
            self._checkbox_group(
                "Pattern optimization",
                [
                    ("Alternatives with same low 4 bits are folding", self.cFoldSameLow4bit),
                    ("Alternatives with same high 4 bits are folding", self.cFoldSameHigh4bit),
                    ("Strip trailing wildcards", self.cStripWildCards),
                    ("Branch short/near encoding variants", self.cBranchEncodingVariants),
                    ("Weighted block voting (strong blocks only)", self.cWeightedBlockVoting),
                    ("Atom governor (keep a fixed-byte anchor per block)", self.cAtomGovernor),
                    ("Hold REX.W fixed (operand-size precise)", self.cRexOperandSizeFixed),
                    ("Stack-frame disp8/disp32 size variants", self.cStackDispSizeVariants),
                    ("Accumulator short/generic encoding variants", self.cAccumulatorEncodingVariants),
                    ("Inter-instruction gap wildcards (tolerate inserted NOPs/padding)", self.cInterInstructionGaps),
                ],
            ),
            self._checkbox_group(
                "Immediate value",
                [
                    ("All constants parametrisation", self.cImmediateParam),
                    ("SP/BP constants parametrisation", self.cSImmParam),
                    ("GP registers constants parametrisation", self.cGpImmParam),
                ],
            ),
            self._checkbox_group(
                "Displacement",
                [
                    ("SP/BP displacement parametrisation", self.cSDisplacementParam),
                    ("GP displacement parametrisation", self.cGpDisplacementParam),
                ],
            ),
        ):
            content_layout.addWidget(group)

        content_layout.addStretch(1)
        scroll_area.setWidget(content)
        main_layout.addWidget(scroll_area)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        main_layout.addWidget(buttons)

        self._apply_gp_master(self.cGpRegistersParam.checked)
        self._apply_sp_master(self.cSRegistersParam.checked)

        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            self._checkbox_widgets.clear()
            self._address_buttons = []
            self._offset_buttons = []
            return 0

        self._sync_from_widgets()
        self._checkbox_widgets.clear()
        self._address_buttons = []
        self._offset_buttons = []
        return 1

    def set_default_check_box_values(self):
        self.cGpRegistersParam.checked = self.is_gp_enabled
        self.cSRegistersParam.checked = self.is_sp_enabled
        self.cFoldSameHigh4bit.checked = True
        self.cFoldSameLow4bit.checked = True
        self.cSImmParam.checked = True
        self.cStripWildCards.checked = True
        self.cBranchEncodingVariants.checked = True
        self.cWeightedBlockVoting.checked = True
        self.cAtomGovernor.checked = True
        self.cRexOperandSizeFixed.checked = True
        self.cStackDispSizeVariants.checked = True
        self.cAccumulatorEncodingVariants.checked = True
        self.cSDisplacementParam.checked = True
        self.check_all_gp(self.is_gp_enabled)
        self.check_all_sp(self.is_sp_enabled)

    def check_all_gp(self, state, update=False):
        for control in self.gp_chk_regs:
            control.checked = state
        all_gp = [
            X86_REG_AH,
            X86_REG_AL,
            X86_REG_AX,
            X86_REG_EAX,
            X86_REG_RAX,
            X86_REG_DH,
            X86_REG_DL,
            X86_REG_DX,
            X86_REG_EDX,
            X86_REG_RDX,
            X86_REG_CH,
            X86_REG_CL,
            X86_REG_CX,
            X86_REG_ECX,
            X86_REG_RCX,
            X86_REG_BH,
            X86_REG_BL,
            X86_REG_BX,
            X86_REG_EBX,
            X86_REG_RBX,
            X86_REG_SIL,
            X86_REG_SI,
            X86_REG_ESI,
            X86_REG_RSI,
            X86_REG_DIL,
            X86_REG_EDI,
            X86_REG_RDI,
            X86_REG_R8B,
            X86_REG_R8W,
            X86_REG_R8D,
            X86_REG_R8,
            X86_REG_R9B,
            X86_REG_R9W,
            X86_REG_R9D,
            X86_REG_R9,
            X86_REG_R10B,
            X86_REG_R10W,
            X86_REG_R10D,
            X86_REG_R10,
            X86_REG_R11B,
            X86_REG_R11W,
            X86_REG_R11D,
            X86_REG_R11,
            X86_REG_R12B,
            X86_REG_R12W,
            X86_REG_R12D,
            X86_REG_R12,
            X86_REG_R13B,
            X86_REG_R13W,
            X86_REG_R13D,
            X86_REG_R13,
            X86_REG_R14B,
            X86_REG_R14W,
            X86_REG_R14D,
            X86_REG_R14,
            X86_REG_R15B,
            X86_REG_R15W,
            X86_REG_R15D,
            X86_REG_R15,
        ]
        self.gp_regs = list(dict.fromkeys(self.gp_regs + all_gp)) if state else []
        if update:
            for control in self.gp_chk_regs:
                self._set_widget_checked(control, state)

    def check_all_sp(self, state, update=False):
        for control in self.sp_chk_regs:
            control.checked = state
        all_sp = [X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP, X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP]
        self.sp_regs = list(dict.fromkeys(self.sp_regs + all_sp)) if state else []
        if update:
            for control in self.sp_chk_regs:
                self._set_widget_checked(control, state)

    def fill_gp_collection_by_control_state(self, control, regs):
        self.gp_regs = (
            list(dict.fromkeys(self.gp_regs + regs)) if control.checked else [x for x in self.gp_regs if x not in regs]
        )

    def fill_sp_collection_by_control_state(self, control, regs):
        self.sp_regs = (
            list(dict.fromkeys(self.sp_regs + regs)) if control.checked else [x for x in self.sp_regs if x not in regs]
        )

    def _registers_group(self):
        group = QtWidgets.QGroupBox("Registers")
        layout = QtWidgets.QVBoxLayout(group)
        gp_master = self._checkbox("GP registers parametrisation", self.cGpRegistersParam)
        sp_master = self._checkbox("SP/BP registers parametrisation", self.cSRegistersParam)
        gp_master.toggled.connect(self._apply_gp_master)
        sp_master.toggled.connect(self._apply_sp_master)
        layout.addWidget(gp_master)
        layout.addWidget(sp_master)
        layout.addWidget(
            self._selector_group(
                "GP selector",
                [
                    ("(E/R/H/L)AX", self.iAX),
                    ("(E/R/H/L)DX", self.iDX),
                    ("(E/R/H/L)CX", self.iCX),
                    ("(E/R/H/L)BX", self.iBX),
                    ("(E/R/H/L)SI", self.iSI),
                    ("(E/R/H/L)DI", self.iDI),
                ],
                3,
            )
        )
        layout.addWidget(
            self._selector_group(
                "GP64 selector",
                [
                    ("(R/D/W)R8", self.iR8),
                    ("(R/D/W)R9", self.iR9),
                    ("(R/D/W)R10", self.iR10),
                    ("(R/D/W)R11", self.iR11),
                    ("(R/D/W)R12", self.iR12),
                    ("(R/D/W)R13", self.iR13),
                    ("(R/D/W)R14", self.iR14),
                    ("(R/D/W)R15", self.iR15),
                ],
                4,
            )
        )
        layout.addWidget(self._selector_group("SP selector", [("(E/R/H/L)SP", self.iSP), ("(E/R/H/L)BP", self.iBP)], 2))
        return group

    def _selector_group(self, title, controls, columns):
        group = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QGridLayout(group)
        for index, (label, control) in enumerate(controls):
            layout.addWidget(self._checkbox(label, control), index // columns, index % columns)
        return group

    def _checkbox_group(self, title, controls):
        group = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(group)
        for label, control in controls:
            layout.addWidget(self._checkbox(label, control))
        return group

    def _radio_group(self, title, labels, checked_index, target_attr):
        group = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(group)
        buttons = []
        for index, label in enumerate(labels):
            button = QtWidgets.QRadioButton(label)
            button.setChecked(index == checked_index)
            layout.addWidget(button)
            buttons.append(button)
        setattr(self, target_attr, buttons)
        return group

    def _checkbox(self, label, control):
        checkbox = QtWidgets.QCheckBox(label)
        checkbox.setChecked(control.checked)
        self._checkbox_widgets[id(control)] = checkbox
        return checkbox

    def _set_widget_checked(self, control, state):
        widget = self._checkbox_widgets.get(id(control))
        if widget is not None:
            widget.setChecked(state)

    def _apply_gp_master(self, enabled):
        for control in self.gp_chk_regs:
            widget = self._checkbox_widgets.get(id(control))
            if widget is not None:
                widget.setEnabled(bool(enabled))
                widget.setChecked(bool(enabled))

    def _apply_sp_master(self, enabled):
        for control in self.sp_chk_regs:
            widget = self._checkbox_widgets.get(id(control))
            if widget is not None:
                widget.setEnabled(bool(enabled))
                widget.setChecked(bool(enabled))

    def _sync_from_widgets(self):
        for control in self._all_controls():
            widget = self._checkbox_widgets.get(id(control))
            if widget is not None:
                control.checked = widget.isChecked()
        self.address_parameterization_mode = self._checked_button_index(self._address_buttons)
        self.offset_parameterization_mode = self._checked_button_index(self._offset_buttons)
        self.is_gp_enabled = self.cGpRegistersParam.checked
        self.is_sp_enabled = self.cSRegistersParam.checked
        self.gp_regs = []
        self.sp_regs = []
        for control, regs, callback in self._register_groups():
            callback(control, regs)

    def _all_controls(self):
        return [value for value in self.__dict__.values() if isinstance(value, _CheckControl)]

    def _register_groups(self):
        return [
            (
                self.iAX,
                [X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iDX,
                [X86_REG_DH, X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iCX,
                [X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iBX,
                [X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX],
                self.fill_gp_collection_by_control_state,
            ),
            (self.iSI, [X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI], self.fill_gp_collection_by_control_state),
            (self.iDI, [X86_REG_DIL, X86_REG_EDI, X86_REG_RDI], self.fill_gp_collection_by_control_state),
            (self.iSP, [X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP], self.fill_sp_collection_by_control_state),
            (self.iBP, [X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP], self.fill_sp_collection_by_control_state),
            (self.iR8, [X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8], self.fill_gp_collection_by_control_state),
            (self.iR9, [X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9], self.fill_gp_collection_by_control_state),
            (
                self.iR10,
                [X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iR11,
                [X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iR12,
                [X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iR13,
                [X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iR14,
                [X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14],
                self.fill_gp_collection_by_control_state,
            ),
            (
                self.iR15,
                [X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15],
                self.fill_gp_collection_by_control_state,
            ),
        ]

    def _checked_button_index(self, buttons):
        for index, button in enumerate(buttons):
            if button.isChecked():
                return index
        return 0
