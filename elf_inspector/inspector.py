"""
inspector.py — Main API entry point: ElfInspector.
"""

from __future__ import annotations

from typing import List, Optional

from .dwarf_parser import DwarfIndex, AddressInfo, GlobalInfo, MemberInfo
from .dwarf_parser import _StructType, _TypedefType, _ConstVolatileType, _ArrayType
from .type_resolver import AddressResolver, resolve_type, type_name_of, size_of
from .line_resolver import LineInfo, CallStack


class ElfInspector:
    """
    ELF variable address inspection tool.

    Loads an ELF file and builds a DWARF index once, then supports
    arbitrary queries.

    Usage::

        insp = ElfInspector("firmware.elf")

        # Simple global variable
        addr = insp.get_address("g_speed")

        # Struct member
        addr = insp.get_address("g_config.uart.baud_rate")

        # Array element
        addr = insp.get_address("g_buf[3]")

        # Mixed
        addr = insp.get_address("g_arr[1].field")

        # Full info
        info = insp.get_info("g_config.uart.baud_rate")
    """

    def __init__(self, elf_path: str):
        """
        Load and parse an ELF file.

        :param elf_path: Path to the ELF file
        :raises ValueError: If the ELF does not contain debug info
        :raises FileNotFoundError: If the file does not exist
        """
        self._path = elf_path
        self._index = DwarfIndex(elf_path)
        self._resolver = AddressResolver(self._index)

    # ------------------------------------------------------------------
    # PC address → source location
    # ------------------------------------------------------------------

    def pc2line(self, addr: int) -> Optional[LineInfo]:
        """
        Resolve a single PC address to source filename, line number, and function name.

        :param addr: PC address (integer)
        :returns: LineInfo, or None if not found
        """
        resolver = self._index.get_line_resolver()
        return resolver.resolve(addr)

    def pc2line_stack(self, addrs: List[int]) -> CallStack:
        """
        Resolve a list of PC addresses into a full call stack.

        :param addrs: PC addresses in call order (top of stack first)
        :returns: CallStack
        """
        resolver = self._index.get_line_resolver()
        return resolver.resolve_stack(addrs)

    # ------------------------------------------------------------------
    # Main query APIs
    # ------------------------------------------------------------------

    def get_address(self, expr: str) -> int:
        """
        Resolve the physical address of a variable or member.

        :param expr: Expression like "g_var", "g_cfg.field", "g_arr[2]"
        :returns: Physical address (integer)
        :raises KeyError: Variable/member not found
        :raises TypeError: Type mismatch
        :raises IndexError: Array subscript out of bounds
        """
        return self._resolver.resolve(expr).address

    def get_info(self, expr: str) -> AddressInfo:
        """
        Resolve full information for a variable or member.
        If the result type is a struct, expands all members recursively.

        :param expr: Expression
        :returns: AddressInfo with address, size, type_name, chain, members
        """
        info = self._resolver.resolve(expr)

        # Ensure DWARF parsing is triggered even for simple variables
        var_name = expr.split('.')[0].split('[')[0]
        type_off = self._index.parse_cu_for_var(var_name)

        # Get the type offset at the end of the expression path
        final_type_off = self._get_final_type_offset(expr, type_off)

        if final_type_off is not None:
            info.size = size_of(final_type_off, self._index)
            info.type_name = type_name_of(final_type_off, self._index)

            try:
                node = resolve_type(final_type_off, self._index)
                if isinstance(node, _StructType):
                    for m in sorted(node.members, key=lambda x: x.byte_offset):
                        m_addr = info.address + m.byte_offset
                        m_tname = type_name_of(m.type_die_offset, self._index)
                        m_size = size_of(m.type_die_offset, self._index)
                        info.members.append((m.name, m_addr, m_size, m_tname, m.type_die_offset))
            except (KeyError, ValueError):
                pass

        return info

    def _get_final_type_offset(self, expr: str, root_type_off: Optional[int]) -> Optional[int]:
        """Walk the expression path to the end, returning the final type's DIE offset."""
        from .type_resolver import parse_expr, resolve_type as _rt
        if root_type_off is None:
            return None

        tokens = parse_expr(expr)
        current = root_type_off

        for tok in tokens[1:]:
            if current is None:
                return None
            try:
                node = _rt(current, self._index)
            except (KeyError, ValueError):
                return None

            if isinstance(tok, str) and isinstance(node, _StructType):
                member = next((m for m in node.members if m.name == tok), None)
                if member is None:
                    return None
                current = member.type_die_offset
            elif isinstance(tok, int) and isinstance(node, _ArrayType):
                current = node.element_type_offset
            else:
                return None

        return current

    # ------------------------------------------------------------------
    # Enumeration APIs
    # ------------------------------------------------------------------

    def list_globals(self) -> List[GlobalInfo]:
        """
        List all global/static variables.

        :returns: List of GlobalInfo, sorted by name
        """
        result: List[GlobalInfo] = []
        for name, var in sorted(self._index.variables.items()):
            if var.address is None:
                continue
            tname = type_name_of(var.type_die_offset, self._index)
            tsize = size_of(var.type_die_offset, self._index)
            result.append(GlobalInfo(
                name=name,
                address=var.address,
                type_name=tname,
                size=tsize,
                type_die_offset=var.type_die_offset or 0,
            ))
        return result

    def list_members(self, type_name: str) -> List[MemberInfo]:
        """
        List all members of a struct/union with their byte offsets.

        Searches typedef and struct/union entries to find the matching type.

        :param type_name: Type name (e.g. "UartConfig")
        :returns: MemberInfo list sorted by offset
        :raises KeyError: If type is not found
        """
        # First check already-resolved types
        struct_node = self._find_struct_by_name(type_name)
        if struct_node is None:
            # Not found: proactively search DWARF top-level DIEs
            cu_offset = self._index.find_type_cu(type_name)
            if cu_offset is not None:
                self._index._parse_cu(cu_offset)
                struct_node = self._find_struct_by_name(type_name)

        if struct_node is None:
            raise KeyError(f"Type {type_name!r} not found; confirm the name is correct.")
        return self._collect_members(struct_node)

    def list_types(self) -> List[str]:
        """
        List all typedef / struct / union type names.

        Scans top-level DIEs across all CUs (fast, no full resolution).

        :returns: Type name list, deduplicated and sorted
        """
        return self._index.collect_all_type_names()

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    def _find_struct_by_name(self, name: str) -> Optional[_StructType]:
        """Find a _StructType by name, supporting typedef aliases."""
        for node in self._index.types.values():
            if isinstance(node, _TypedefType) and node.name == name:
                if node.target_offset is not None:
                    try:
                        real = resolve_type(node.target_offset, self._index)
                        if isinstance(real, _StructType):
                            return real
                    except (KeyError, ValueError):
                        pass

        for node in self._index.types.values():
            if isinstance(node, _StructType) and node.name == name:
                return node

        return None

    def _collect_members(self, struct: _StructType) -> List[MemberInfo]:
        """Collect all struct members, sorted by offset."""
        result: List[MemberInfo] = []
        for m in struct.members:
            tname = type_name_of(m.type_die_offset, self._index)
            tsize = size_of(m.type_die_offset, self._index)
            result.append(MemberInfo(
                name=m.name,
                offset=m.byte_offset,
                type_name=tname,
                size=tsize,
                type_die_offset=m.type_die_offset,
            ))
        result.sort(key=lambda m: m.offset)
        return result

    def __repr__(self):
        n_vars = len(self._index.variables)
        n_types = len(self._index.types)
        return (
            f"ElfInspector({self._path!r}, "
            f"variables={n_vars}, types={n_types})"
        )
