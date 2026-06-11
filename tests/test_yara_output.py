import pytest
import yara_x

from yarg.yara_output import (
    YaraBytePattern,
    YaraInstructionComment,
    YaraOutputError,
    build_code_rule,
    build_function_rule,
    build_yara_rule,
    longest_fixed_run,
    pattern_atom_ok,
    render_byte_string,
    sanitize_identifier,
)


ANNOTATIONS = [
    YaraInstructionComment(0x401000, "558bec", "push rbp"),
    YaraInstructionComment(0x401003, "4889e5", "mov rbp, rsp"),
]


def test_render_byte_string_sanitizes_name_and_keeps_pattern():
    rendered = render_byte_string(YaraBytePattern("$code-at:401000", "558BEC"))

    assert rendered == "    $code_at_401000 = { 558BEC }"


def test_comments_include_raw_hex_and_disassembly_without_extra_columns():
    rendered = render_byte_string(YaraBytePattern("$code_at_00401000", "558BEC", ANNOTATIONS))

    assert "     * 558bec | push rbp" in rendered
    assert "     * 4889e5 | mov rbp, rsp" in rendered
    assert "opcode" not in rendered.lower()
    assert "pattern bytes" not in rendered.lower()


def test_comment_hex_column_is_padded_to_align_separator():
    rendered = render_byte_string(
        YaraBytePattern(
            "$code_at_00401000",
            "488B4424388B00",
            [
                YaraInstructionComment(0x401000, "488b442438", "mov rax, qword ptr [rsp + 0x38]"),
                YaraInstructionComment(0x401005, "8b00", "mov eax, dword ptr [rax]"),
            ],
        )
    )

    assert "     * 488b442438 | mov rax, qword ptr [rsp + 0x38]" in rendered
    assert "     * 8b00       | mov eax, dword ptr [rax]" in rendered


def test_generated_single_pattern_rule_is_formatted_and_compiles():
    rule = build_yara_rule(
        "generated rule",
        [YaraBytePattern("$code_at_00401000", "55??8BEC", ANNOTATIONS)],
        "$code_at_00401000",
    )

    assert "rule generated_rule" in rule
    assert "$code_at_00401000 = { 55 ?? 8B EC }" in rule
    assert "push rbp" in rule
    yara_x.compile(rule)


def test_selected_instruction_rule_is_complete_and_uses_single_string_condition():
    rule = build_code_rule(0x401000, "558BEC", ANNOTATIONS, 32, "code_at_", "instr")

    assert "rule generate_rule_instr_00401000" in rule
    assert "strings:" in rule
    assert "$code_at_00401000 = { 55 8B EC }" in rule
    assert "condition:" in rule
    assert "$code_at_00401000" in rule
    yara_x.compile(rule)


@pytest.mark.parametrize("rule_kind", ["instr", "bb"])
def test_single_address_code_rules_use_full_64_bit_address_names(rule_kind):
    rule = build_code_rule(0x140001000, "C3", ANNOTATIONS, 64, "code_at_", rule_kind)

    assert f"rule generate_rule_{rule_kind}_0000000140001000" in rule
    assert "$code_at_0000000140001000 = { C3 }" in rule
    assert "$code_at_40001000" not in rule
    yara_x.compile(rule)


def test_selected_range_rule_is_complete_not_raw_variable_only():
    rule = build_code_rule(0x401000, "558BEC", ANNOTATIONS, 32, "code_at_", "range", rule_end_ea=0x401006)

    assert "rule generate_rule_range_00401000_00401006" in rule
    assert "strings:" in rule
    assert "condition:" in rule
    assert "$code_at_00401000 = { 55 8B EC }" in rule
    assert rule.strip().endswith("}")
    yara_x.compile(rule)


def test_selected_range_rule_uses_full_64_bit_start_and_end_names():
    rule = build_code_rule(
        0x140001000,
        "558BEC",
        ANNOTATIONS,
        64,
        "code_at_",
        "range",
        rule_end_ea=0x140001006,
    )

    assert "rule generate_rule_range_0000000140001000_0000000140001006" in rule
    assert "$code_at_0000000140001000 = { 55 8B EC }" in rule
    assert "$code_at_40001000" not in rule
    yara_x.compile(rule)


def test_selected_basic_block_rule_is_complete_not_raw_variable_only():
    rule = build_code_rule(0x401020, "C3", [YaraInstructionComment(0x401020, "c3", "ret")], 32, "code_at_", "bb")

    assert "rule generate_rule_bb_00401020" in rule
    assert "strings:" in rule
    assert "condition:" in rule
    assert "$code_at_00401020 = { C3 }" in rule
    yara_x.compile(rule)


def test_function_rule_uses_32_bit_addresses_and_threshold_condition():
    rule = build_function_rule(
        0x401000,
        [(0x401000, "558BEC", ANNOTATIONS), (0x401010, "C3", [YaraInstructionComment(0x401010, "c3", "ret")])],
        32,
        "code_at_",
    )

    assert "rule generate_rule_fn_00401000" in rule
    assert "$code_at_00401000" in rule
    assert "$code_at_00401010" in rule
    assert "2 of ($code_at_*)" in rule
    yara_x.compile(rule)


def test_function_rule_uses_64_bit_addresses():
    rule = build_function_rule(
        0x140001000,
        [(0x140001000, "488BC1C3", [YaraInstructionComment(0x140001000, "488bc1c3", "mov rax, rcx")])],
        64,
        "code_at_",
    )

    assert "rule generate_rule_fn_0000000140001000" in rule
    assert "$code_at_0000000140001000" in rule
    assert "1 of ($code_at_*)" in rule
    yara_x.compile(rule)


def test_function_rule_keeps_distinct_64_bit_block_string_names():
    rule = build_function_rule(
        0x140001000,
        [
            (0x140001000, "C3", [YaraInstructionComment(0x140001000, "c3", "ret")]),
            (0x240001000, "90", [YaraInstructionComment(0x240001000, "90", "nop")]),
        ],
        64,
        "code_at_",
    )

    assert "$code_at_0000000140001000" in rule
    assert "$code_at_0000000240001000" in rule
    assert "$code_at_40001000" not in rule
    yara_x.compile(rule)


def test_validation_error_reports_yara_x_compile_failure():
    with pytest.raises(YaraOutputError, match="failed validation"):
        build_yara_rule("bad", [YaraBytePattern("$bad", "GG")], "$bad")


def test_identifier_sanitization_never_returns_invalid_empty_identifier():
    assert sanitize_identifier("!!!", "fallback") == "fallback"
    assert sanitize_identifier("123 name", "fallback") == "_123_name"


def test_build_yara_rule_falls_back_when_formatter_is_missing(monkeypatch):
    monkeypatch.setattr(yara_x, "Formatter", None)
    rule = build_yara_rule("test_rule", [YaraBytePattern("$str", "558BEC", ANNOTATIONS)], "$str")
    assert "rule test_rule" in rule
    assert "$str = { 558BEC }" in rule or "$str = { 55 8B EC }" in rule
    yara_x.compile(rule)


def test_build_yara_rule_falls_back_when_formatter_raises_exception(monkeypatch):
    class BadFormatter:
        def format(self, *args, **kwargs):
            raise ValueError("Formatting failed")

    monkeypatch.setattr(yara_x, "Formatter", BadFormatter)
    rule = build_yara_rule("test_rule", [YaraBytePattern("$str", "558BEC", ANNOTATIONS)], "$str")
    assert "rule test_rule" in rule
    yara_x.compile(rule)


def test_function_rule_threshold_caps_correctly_for_single_block():
    rule = build_function_rule(
        0x401000,
        [(0x401000, "558BEC", ANNOTATIONS)],
        32,
        "code_at_",
    )
    assert "1 of ($code_at_*)" in rule


def test_function_rule_threshold_caps_correctly_for_five_blocks():
    # 5 blocks: half_plus_one = (5 // 2) + 1 = 3
    # required = min(3 + 3 // 2, 5) = min(4, 5) = 4
    blocks = [(0x401000 + i * 0x10, "90", [YaraInstructionComment(0x401000 + i * 0x10, "90", "nop")]) for i in range(5)]
    rule = build_function_rule(0x401000, blocks, 32, "code_at_")
    assert "4 of ($code_at_*)" in rule


def test_longest_fixed_run_counts_contiguous_fixed_bytes():
    assert longest_fixed_run("558BEC") == 3
    assert longest_fixed_run("55??8BEC") == 2  # the 8B EC run; the 55 run is broken by ??
    assert longest_fixed_run("E8????") == 1
    assert longest_fixed_run("90") == 1


def test_longest_fixed_run_treats_alternation_groups_as_breaks():
    # A group yields no global atom, so it breaks the surrounding fixed run.
    assert longest_fixed_run("90(74??|0F84????)90") == 1
    assert longest_fixed_run("(EB??|E9????)") == 0
    # Fixed bytes adjacent to (but outside) the group still count.
    assert longest_fixed_run("8BEC(C0|C1)") == 2


def test_pattern_atom_ok_threshold():
    assert pattern_atom_ok("8BEC")          # 2-byte run
    assert not pattern_atom_ok("E8????")    # only a 1-byte opcode anchor
    assert not pattern_atom_ok("(EB??|E9????)")
    assert pattern_atom_ok("8B", min_atom=1)


# ---------------------------------------------------------------------------
# R7: weighted_voting tests
# ---------------------------------------------------------------------------

def test_weighted_voting_drops_weak_keeps_strong():
    # 558BEC is strong (3-byte fixed run); C3 is weak (1-byte fixed run).
    # With weighted_voting=True only the strong block should be emitted and
    # the condition should reflect the strong-only count (1 of ...).
    rule = build_function_rule(
        0x401000,
        [
            (0x401000, "558BEC", ANNOTATIONS),
            (0x401010, "C3", [YaraInstructionComment(0x401010, "c3", "ret")]),
        ],
        32,
        "code_at_",
        weighted_voting=True,
    )

    assert "$code_at_00401000" in rule          # strong block present
    assert "$code_at_00401010" not in rule       # weak block dropped
    assert "1 of ($code_at_*)" in rule           # threshold over 1 strong block
    yara_x.compile(rule)


def test_weighted_voting_all_weak_falls_back_to_flat():
    # Both blocks are weak (single-byte patterns).  Fall-back: emit all with
    # the flat formula.  2 blocks → half_plus_one=2, required=min(3,2)=2.
    rule = build_function_rule(
        0x401000,
        [
            (0x401000, "90", [YaraInstructionComment(0x401000, "90", "nop")]),
            (0x401001, "C3", [YaraInstructionComment(0x401001, "c3", "ret")]),
        ],
        32,
        "code_at_",
        weighted_voting=True,
    )

    assert "$code_at_00401000" in rule           # both blocks present
    assert "$code_at_00401001" in rule
    assert "2 of ($code_at_*)" in rule           # flat threshold for 2 blocks
    yara_x.compile(rule)


def test_weighted_voting_false_identical_to_default():
    # Explicitly passing weighted_voting=False must produce the same output as
    # calling with no extra args (the legacy flat behavior).
    blocks = [
        (0x401000, "558BEC", ANNOTATIONS),
        (0x401010, "C3", [YaraInstructionComment(0x401010, "c3", "ret")]),
    ]
    rule_default = build_function_rule(0x401000, blocks, 32, "code_at_")
    rule_explicit = build_function_rule(0x401000, blocks, 32, "code_at_", weighted_voting=False)

    assert rule_default == rule_explicit
    # Both blocks are emitted and the condition covers the full set.
    assert "$code_at_00401000" in rule_default
    assert "$code_at_00401010" in rule_default
    assert "2 of ($code_at_*)" in rule_default
    yara_x.compile(rule_default)


def test_weighted_voting_multiple_strong_threshold():
    # 3 strong blocks, 2 weak blocks.
    # Weighted path keeps 3 strong blocks.
    # half_plus_one = (3//2)+1 = 2 ; required = min(2 + 2//2, 3) = min(3, 3) = 3
    strong_block = "558BEC"   # 3-byte fixed run — strong
    weak_block = "C3"         # 1-byte fixed run — weak

    blocks = [
        (0x401000, strong_block, [YaraInstructionComment(0x401000, "558bec", "push rbp")]),
        (0x401010, strong_block, [YaraInstructionComment(0x401010, "558bec", "push rbp")]),
        (0x401020, strong_block, [YaraInstructionComment(0x401020, "558bec", "push rbp")]),
        (0x401030, weak_block,   [YaraInstructionComment(0x401030, "c3", "ret")]),
        (0x401040, weak_block,   [YaraInstructionComment(0x401040, "c3", "ret")]),
    ]
    rule = build_function_rule(0x401000, blocks, 32, "code_at_", weighted_voting=True)

    assert "$code_at_00401000" in rule
    assert "$code_at_00401010" in rule
    assert "$code_at_00401020" in rule
    assert "$code_at_00401030" not in rule       # weak — dropped
    assert "$code_at_00401040" not in rule       # weak — dropped
    assert "3 of ($code_at_*)" in rule
    yara_x.compile(rule)
