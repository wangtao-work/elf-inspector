"""
line_resolver.py — PC address → source filename + line number + function name.

Two index tables:
  line_table : List[(address, filename, lineno)]  sorted by address
               Source: .debug_line DWARF line number state machine
  func_table : List[(low_pc, high_pc, name)]      sorted by low_pc
               Source: STT_FUNC entries in .symtab

Query algorithm: binary search, O(log n).

Works with any compiler (GCC / HighTec / Tasking / GHS / IAR)
as long as the ELF contains standard DWARF debug info.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass
class LineInfo:
    """Resolution result for a single PC address."""
    address: int
    filename: str           # Compilation-time path (absolute)
    lineno: int             # Line number
    func_name: str          # Function name, "<unknown>" if not found
    inlined: bool = False   # Whether this is an inlined function location

    def __str__(self):
        return f"{self.filename}:{self.lineno}  {self.func_name}"


@dataclass
class CallStack:
    """Full call stack representation."""
    frames: List[Tuple[int, Optional[LineInfo]]]  # (address, LineInfo or None)

    def __str__(self):
        lines = []
        for i, (addr, info) in enumerate(self.frames):
            if info:
                lines.append(f"#{i:<3} 0x{addr:08x}  {info}")
            else:
                lines.append(f"#{i:<3} 0x{addr:08x}  <no debug info>")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Index builders
# ---------------------------------------------------------------------------

def build_line_table(elf_path: str) -> List[Tuple[int, str, int]]:
    """
    Parse .debug_line and build a line number table.
    Returns [(address, filename, lineno), ...] sorted by address ascending.
    """
    from elftools.elf.elffile import ELFFile
    import os

    table: List[Tuple[int, str, int]] = []

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return table
        dwarf = elf.get_dwarf_info()

        for cu in dwarf.iter_CUs():
            lp = dwarf.line_program_for_CU(cu)
            if lp is None:
                continue

            file_entries = lp["file_entry"]
            include_dirs = lp["include_directory"]

            # Extract compilation directory (absolute path) for resolving relative paths
            _comp_dir_attr = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
            _comp_dir = ""
            if _comp_dir_attr:
                _comp_dir = _comp_dir_attr.value
                if isinstance(_comp_dir, bytes):
                    _comp_dir = _comp_dir.decode("utf-8", errors="replace")
                _comp_dir = _comp_dir.replace("\\", "/")

            def _abs(path: str) -> str:
                """If path is relative, prepend comp_dir and normalize to absolute."""
                path = path.replace("\\", "/")
                if os.path.isabs(path):
                    return os.path.normpath(path).replace("\\", "/")
                if _comp_dir:
                    return os.path.normpath(_comp_dir + "/" + path).replace("\\", "/")
                return path

            def resolve_filename(file_idx: int) -> str:
                """Resolve a file_index to a full absolute path."""
                if file_idx < 1 or file_idx > len(file_entries):
                    return "?"
                fe = file_entries[file_idx - 1]
                name = fe.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                name = name.replace("\\", "/")

                dir_idx = fe.dir_index
                if dir_idx == 0:
                    return _abs(name)
                else:
                    if dir_idx <= len(include_dirs):
                        d = include_dirs[dir_idx - 1]
                        if isinstance(d, bytes):
                            d = d.decode("utf-8", errors="replace")
                        return _abs(d.replace("\\", "/") + "/" + name)
                    return _abs(name)

            for entry in lp.get_entries():
                state = entry.state
                if state is None or state.end_sequence:
                    continue
                if state.address == 0:
                    continue
                filename = resolve_filename(state.file)
                table.append((state.address, filename, state.line))

    table.sort(key=lambda x: x[0])
    return table


def build_func_table(elf_path: str) -> List[Tuple[int, int, str]]:
    """
    Build a function address-range table from STT_FUNC entries in .symtab.
    Returns [(low_pc, high_pc, name), ...] sorted by low_pc ascending.
    """
    from elftools.elf.elffile import ELFFile

    table: List[Tuple[int, int, str]] = []

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return table

        for sym in symtab.iter_symbols():
            if (sym.entry.st_info.type == "STT_FUNC"
                    and sym.entry.st_value != 0
                    and sym.name):
                low  = sym.entry.st_value
                # st_size=0 → placeholder 0, filled in later
                high = low + sym.entry.st_size if sym.entry.st_size > 0 else 0
                table.append((low, high, sym.name))

    table.sort(key=lambda x: x[0])

    # Fill in high=0 entries (functions with st_size=0):
    # Use the next function's low_pc as the upper bound
    for i in range(len(table)):
        if table[i][1] == 0:
            next_low = table[i + 1][0] if i + 1 < len(table) else table[i][0] + 4
            table[i] = (table[i][0], next_low, table[i][2])

    return table


# ---------------------------------------------------------------------------
# Query engine
# ---------------------------------------------------------------------------

class LineResolver:
    """
    Given pre-built line_table and func_table, resolves PC addresses.
    Both tables are sorted lists; queries use binary search.
    """

    def __init__(
        self,
        line_table: List[Tuple[int, str, int]],
        func_table: List[Tuple[int, int, str]],
    ):
        self._line_table = line_table
        self._func_table = func_table
        self._line_addrs = [e[0] for e in line_table]
        self._func_lows  = [e[0] for e in func_table]

    def resolve(self, addr: int) -> Optional[LineInfo]:
        """Resolve a single PC address. Returns LineInfo or None."""
        func_name = self._lookup_func(addr)
        filename, lineno = self._lookup_line(addr, func_name)
        if filename is None:
            return None

        return LineInfo(
            address=addr,
            filename=filename,
            lineno=lineno,
            func_name=func_name,
        )

    def resolve_stack(self, addrs: List[int]) -> CallStack:
        """Resolve a list of PC addresses into a full call stack."""
        frames = []
        for addr in addrs:
            info = self.resolve(addr)
            frames.append((addr, info))
        return CallStack(frames=frames)

    def _lookup_line(self, addr: int, func_name: str = "") -> Tuple[Optional[str], int]:
        """
        Binary search the line table for the closest entry ≤ addr.
        Returns (filename, lineno), or (None, 0) if not found.
        """
        if not self._line_addrs:
            return None, 0

        idx = bisect.bisect_right(self._line_addrs, addr) - 1
        if idx < 0:
            return None, 0

        entry_addr, filename, lineno = self._line_table[idx]

        # Sanity check: if the address is not within any known function
        # and the gap from the nearest line entry exceeds 64 bytes, treat as invalid.
        if func_name == "<unknown>" and addr - entry_addr > 64:
            return None, 0

        return filename, lineno

    def _lookup_func(self, addr: int) -> str:
        """
        Binary search the function table for the entry containing addr.
        Returns function name, or "<unknown>" if not found.
        """
        if not self._func_lows:
            return "<unknown>"

        idx = bisect.bisect_right(self._func_lows, addr) - 1
        if idx < 0:
            return "<unknown>"

        low, high, name = self._func_table[idx]
        if low <= addr < high:
            return name
        return "<unknown>"
