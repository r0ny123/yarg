import io
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

import yara_x


YARA_IDENTIFIER_RE = re.compile(r"[^A-Za-z0-9_]")


class YaraOutputError(Exception):
    """Raised when generated YARA output cannot be rendered or compiled."""


@dataclass(frozen=True)
class YaraInstructionComment:
    ea: int
    raw_bytes: str
    disassembly: str


@dataclass(frozen=True)
class YaraBytePattern:
    name: str
    pattern: str
    annotations: Sequence[YaraInstructionComment] = ()


def sanitize_identifier(value: str, fallback: str) -> str:
    identifier = YARA_IDENTIFIER_RE.sub("_", value.strip())

    if not identifier.strip("_"):
        identifier = fallback

    if identifier[0].isdigit():
        identifier = f"_{identifier}"

    return identifier


def sanitize_string_identifier(value: str, fallback: str) -> str:
    identifier = sanitize_identifier(value.lstrip("$"), fallback)
    return f"${identifier}"


def _compact_hex(value: str) -> str:
    return re.sub(r"\s+", "", value).lower()


def _safe_comment_text(value: str) -> str:
    return value.replace("*/", "* /").strip()


def render_instruction_comments(annotations: Sequence[YaraInstructionComment]) -> str:
    if not annotations:
        return ""

    raw_bytes_by_line = [_compact_hex(str(annotation.raw_bytes)) for annotation in annotations]
    raw_width = max(len(raw_bytes) for raw_bytes in raw_bytes_by_line)

    lines = ["    /*"]
    for annotation, raw_bytes in zip(annotations, raw_bytes_by_line):
        disassembly = _safe_comment_text(str(annotation.disassembly))
        lines.append(f"     * {raw_bytes:<{raw_width}} | {disassembly}")

    lines.append("     */")
    return "\n".join(lines)


def render_byte_string(pattern: YaraBytePattern) -> str:
    name = sanitize_string_identifier(pattern.name, "pattern")
    byte_pattern = pattern.pattern.strip()

    if not byte_pattern:
        raise YaraOutputError(f"YARA string {name} has an empty byte pattern")

    rendered = f"    {name} = {{ {byte_pattern} }}"
    comments = render_instruction_comments(pattern.annotations)
    if comments:
        return f"{comments}\n{rendered}"

    return rendered


def render_rule_source(rule_name: str, patterns: Sequence[YaraBytePattern], condition: str) -> str:
    safe_rule_name = sanitize_identifier(rule_name, "generated_rule")
    condition = condition.strip()

    if not patterns:
        raise YaraOutputError("Cannot build a YARA rule without strings")

    if not condition:
        raise YaraOutputError("Cannot build a YARA rule without a condition")

    strings = "\n".join(render_byte_string(pattern) for pattern in patterns)

    return f"rule {safe_rule_name} {{\n  strings:\n{strings}\n\n  condition:\n    {condition}\n}}\n"


def format_yara_source(source: str) -> str:
    try:
        formatter_cls = getattr(yara_x, "Formatter", None)
        if formatter_cls is None:
            return source
        output = io.StringIO()
        formatter_cls().format(io.StringIO(source), output)
        return output.getvalue()
    except Exception:
        return source


def validate_yara_source(source: str) -> None:
    try:
        yara_x.compile(source)
    except yara_x.CompileError as exc:
        raise YaraOutputError(f"Generated YARA rule failed validation: {exc}") from exc


def build_yara_rule(rule_name: str, patterns: Sequence[YaraBytePattern], condition: str) -> str:
    source = render_rule_source(rule_name, patterns, condition)
    validate_yara_source(source)

    formatted = format_yara_source(source)
    validate_yara_source(formatted)

    return formatted


def address_width_for_bitness(bitness: int) -> int:
    return 16 if bitness == 64 else 8


def format_rule_address(ea: int, bitness: int) -> str:
    return f"{ea:0{address_width_for_bitness(bitness)}X}"


def build_code_rule(
    rule_ea: int,
    pattern: str,
    annotations: Sequence[YaraInstructionComment],
    bitness: int,
    var_prefix: str,
    rule_kind: str,
    rule_end_ea: int | None = None,
) -> str:
    formatted_start = format_rule_address(rule_ea, bitness)
    string_name = f"{var_prefix}{formatted_start}"
    safe_kind = sanitize_identifier(rule_kind, "code")
    rule_name = f"generate_rule_{safe_kind}_{formatted_start}"

    if rule_end_ea is not None:
        rule_name = f"{rule_name}_{format_rule_address(rule_end_ea, bitness)}"

    return build_yara_rule(
        rule_name,
        [YaraBytePattern(string_name, pattern, annotations)],
        sanitize_string_identifier(string_name, "code_at"),
    )


def build_function_rule(
    rule_ea: int,
    block_patterns: Iterable[tuple[int, str, Sequence[YaraInstructionComment]]],
    bitness: int,
    var_prefix: str,
) -> str:
    patterns = [
        YaraBytePattern(f"{var_prefix}{format_rule_address(block_ea, bitness)}", pattern, annotations)
        for block_ea, pattern, annotations in block_patterns
    ]

    half_plus_one = (len(patterns) // 2) + 1
    required = min(half_plus_one + half_plus_one // 2, len(patterns))
    condition = f"{required} of (${sanitize_identifier(var_prefix, 'code_at')}*)"
    rule_name = f"generate_rule_fn_{format_rule_address(rule_ea, bitness)}"

    return build_yara_rule(rule_name, patterns, condition)
