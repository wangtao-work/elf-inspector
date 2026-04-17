"""
type_resolver.py — Expression parsing + address computation.

Responsibilities:
  1. Parse input strings (e.g. "g_config.uart.baud_rate" or "g_buf[3]")
     into a token sequence.
  2. Recursively compute the final address based on the DwarfIndex.
"""

from __future__ import annotations

import re
from typing import List, Union, Tuple, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .dwarf_parser import DwarfIndex, AddressInfo

from .dwarf_parser import (
    AddressInfo,
    _BaseType, _PointerType, _TypedefType,
    _ConstVolatileType, _EnumType, _StructType, _ArrayType,
    _StructMember, TypeNode,
)


# ---------------------------------------------------------------------------
# Expression Tokenizer
# ---------------------------------------------------------------------------

# Token type: string identifier or integer subscript
Token = Union[str, int]


def parse_expr(expr: str) -> List[Token]:
    """
    Parse an expression string into a list of tokens.

    Examples:
      "g_speed"              → ["g_speed"]
      "g_config.uart.baud"   → ["g_config", "uart", "baud"]
      "g_buf[3]"             → ["g_buf", 3]
      "g_arr[1].field"       → ["g_arr", 1, "field"]
      "g_matrix[2][3]"       → ["g_matrix", 2, 3]
    """
    expr = expr.strip()
    if not expr:
        raise ValueError("Expression must not be empty")

    tokens: List[Token] = []
    pattern = re.compile(r'([A-Za-z_]\w*)|(\[(\d+)\])')
    pos = 0
    while pos < len(expr):
        if expr[pos] == '.':
            pos += 1
            continue
        m = pattern.match(expr, pos)
        if m is None:
            raise ValueError(
                f"Cannot parse expression {expr!r} at position {pos}: {expr[pos:]!r}"
            )
        if m.group(1):
            tokens.append(m.group(1))  # identifier
        else:
            tokens.append(int(m.group(3)))  # array subscript
        pos = m.end()

    if not tokens:
        raise ValueError(f"Expression {expr!r} produced no tokens")
    if not isinstance(tokens[0], str):
        raise ValueError(f"Expression must start with a variable name, got: {tokens[0]!r}")

    return tokens


# ---------------------------------------------------------------------------
# Type utilities
# ---------------------------------------------------------------------------

def resolve_type(type_offset: int, index: "DwarfIndex") -> TypeNode:
    """
    Look up a type by type_offset, transparently unwrapping typedef / const / volatile.
    Returns the underlying type node.
    """
    seen = set()
    current_offset = type_offset
    while current_offset is not None:
        if current_offset in seen:
            raise ValueError(f"Circular type reference at offset=0x{current_offset:x}")
        seen.add(current_offset)

        node = index.types.get(current_offset)
        if node is None:
            raise KeyError(
                f"Type DIE offset=0x{current_offset:x} not found; "
                "debug info may be incomplete."
            )
        if isinstance(node, (_TypedefType, _ConstVolatileType)):
            current_offset = node.target_offset
        else:
            return node

    raise KeyError(f"Type offset=0x{type_offset:x} could not be resolved (empty reference chain)")


def type_name_of(type_offset: Optional[int], index: "DwarfIndex") -> str:
    """
    Return a human-readable type name (real name, not the typedef alias).
    Prefers the typedef name for display, falls back to the underlying type name.
    """
    if type_offset is None:
        return "<unknown>"
    node = index.types.get(type_offset)
    if node is None:
        return "<unknown>"
    if isinstance(node, _TypedefType):
        return node.name or type_name_of(node.target_offset, index)
    if isinstance(node, _ConstVolatileType):
        return type_name_of(node.target_offset, index)
    if isinstance(node, _BaseType):
        return node.name
    if isinstance(node, _StructType):
        prefix = "union" if node.is_union else "struct"
        return f"{prefix} {node.name}" if node.name else f"{prefix} <anonymous>"
    if isinstance(node, _PointerType):
        target = type_name_of(node.target_offset, index)
        return f"{target}*"
    if isinstance(node, _EnumType):
        return f"enum {node.name}" if node.name else "enum <anonymous>"
    if isinstance(node, _ArrayType):
        dims = "".join(
            f"[{d.count}]" if d.count >= 0 else "[]"
            for d in node.dimensions
        )
        elem = type_name_of(node.element_type_offset, index)
        return f"{elem}{dims}"
    return "<unknown>"


def size_of(type_offset: Optional[int], index: "DwarfIndex") -> int:
    """Compute the byte size of a type."""
    if type_offset is None:
        return 0
    try:
        node = resolve_type(type_offset, index)
    except (KeyError, ValueError):
        return 0

    if isinstance(node, _BaseType):
        return node.size
    if isinstance(node, _PointerType):
        return node.size
    if isinstance(node, _EnumType):
        return node.size
    if isinstance(node, _StructType):
        return node.size
    if isinstance(node, _ArrayType):
        elem_size = size_of(node.element_type_offset, index)
        total = elem_size
        for dim in node.dimensions:
            if dim.count < 0:
                return 0
            total *= dim.count
        return total
    return 0


# ---------------------------------------------------------------------------
# Address Resolver
# ---------------------------------------------------------------------------

class AddressResolver:
    """
    Resolves expressions against a DwarfIndex to produce an AddressInfo.
    """

    def __init__(self, index: "DwarfIndex"):
        self._idx = index

    def resolve(self, expr: str) -> AddressInfo:
        tokens = parse_expr(expr)
        var_name = tokens[0]

        if not isinstance(var_name, str):
            raise ValueError(f"First token must be a variable name, got {var_name!r}")

        var_info = self._idx.variables.get(var_name)
        if var_info is None:
            raise KeyError(
                f"Variable {var_name!r} not found. "
                "Possible causes: not a global/static variable, or debug info is missing."
            )
        if var_info.address is None:
            raise ValueError(
                f"Variable {var_name!r} has no static address "
                "(may be a local variable or register variable)."
            )

        base_addr = var_info.address
        cumulative = base_addr

        # Trigger DWARF lazy loading only when expression contains member/subscript
        if len(tokens) > 1:
            current_type_offset = self._idx.parse_cu_for_var(var_name)
            if current_type_offset is None:
                raise ValueError(
                    f"Cannot find type information for variable {var_name!r} in DWARF; "
                    "cannot resolve members/subscripts."
                )
        else:
            current_type_offset = None

        chain: List[Tuple[str, int]] = [(var_name, base_addr)]

        for tok in tokens[1:]:
            if current_type_offset is None and len(tokens) > 1:
                raise ValueError(
                    f"When parsing {tok!r}, the current type is unknown."
                )
            if current_type_offset is None:
                # Simple variable, no further tokens expected
                break

            node = resolve_type(current_type_offset, self._idx)

            if isinstance(tok, str):
                # Member access
                if not isinstance(node, _StructType):
                    tname = type_name_of(current_type_offset, self._idx)
                    raise TypeError(
                        f"Type {tname!r} is not a struct/union, "
                        f"cannot access member {tok!r}."
                    )
                member = self._find_member(node, tok)
                cumulative += member.byte_offset
                current_type_offset = member.type_die_offset
                chain.append((f".{tok}", cumulative))

            elif isinstance(tok, int):
                # Array subscript
                if not isinstance(node, _ArrayType):
                    tname = type_name_of(current_type_offset, self._idx)
                    raise TypeError(
                        f"Type {tname!r} is not an array, cannot use subscript [{tok}]."
                    )
                dim = node.dimensions[0] if node.dimensions else None
                if dim and dim.count >= 0 and tok >= dim.count:
                    raise IndexError(
                        f"Subscript [{tok}] out of bounds (size={dim.count})."
                    )
                elem_size = size_of(node.element_type_offset, self._idx)
                cumulative += tok * elem_size
                current_type_offset = node.element_type_offset
                chain.append((f"[{tok}]", cumulative))

        final_size = size_of(current_type_offset, self._idx)
        final_type = type_name_of(current_type_offset, self._idx)

        return AddressInfo(
            address=cumulative,
            size=final_size,
            type_name=final_type,
            chain=chain,
        )

    def _find_member(self, struct: _StructType, name: str) -> _StructMember:
        for m in struct.members:
            if m.name == name:
                return m
        available = [m.name for m in struct.members]
        raise KeyError(
            f"Struct {struct.name!r} does not have a member {name!r}. "
            f"Available members: {available}"
        )
