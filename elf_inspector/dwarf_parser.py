"""
dwarf_parser.py — ELF/DWARF parser with a two-tier acceleration strategy:

  Tier 1 — Symbol table index (.symtab)
         Cold start ~2s, loaded from disk cache in ~16ms.
         Covers: global variable addresses and sizes.

  Tier 2 — On-demand single-CU DWARF parsing
         Each CU ~70ms, triggered only when type/member info is needed.
         Covers: struct member offsets, type names, array dimensions.

Cache file: <elf_path>.idx, pickle format, invalidated when ELF mtime changes.
"""

from __future__ import annotations

import os
import pickle
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from elftools.elf.elffile import ELFFile


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass
class MemberInfo:
    """Struct member information"""
    name: str
    offset: int
    type_name: str
    size: int
    type_die_offset: int


@dataclass
class GlobalInfo:
    """Global variable information"""
    name: str
    address: int
    type_name: str
    size: int
    type_die_offset: int


@dataclass
class AddressInfo:
    """Query result"""
    address: int
    size: int
    type_name: str
    # Resolution chain: (name_or_index, cumulative_address) per step
    chain: List[Tuple[str, int]] = field(default_factory=list)
    # When the result is a struct, expanded member list:
    # (name, address, size, type_name, type_die_offset)
    members: List[Tuple[str, int, int, str, int]] = field(default_factory=list)

    def __repr__(self):
        chain_str = " -> ".join(
            f"{n}(@0x{a:x})" for n, a in self.chain
        )
        return (
            f"AddressInfo(address=0x{self.address:x}, "
            f"size={self.size}, type={self.type_name}, "
            f"chain=[{chain_str}])"
        )


# ---------------------------------------------------------------------------
# Internal type nodes (used only during DWARF parsing)
# ---------------------------------------------------------------------------

@dataclass
class _BaseType:
    kind: str = "base"
    name: str = ""
    size: int = 0


@dataclass
class _PointerType:
    kind: str = "pointer"
    name: str = ""
    size: int = 4
    target_offset: Optional[int] = None


@dataclass
class _TypedefType:
    kind: str = "typedef"
    name: str = ""
    target_offset: Optional[int] = None


@dataclass
class _ConstVolatileType:
    kind: str = "cv"
    target_offset: Optional[int] = None


@dataclass
class _EnumType:
    kind: str = "enum"
    name: str = ""
    size: int = 4


@dataclass
class _StructMember:
    name: str
    byte_offset: int
    type_die_offset: int


@dataclass
class _StructType:
    kind: str = "struct"
    name: str = ""
    size: int = 0
    is_union: bool = False
    members: List[_StructMember] = field(default_factory=list)


@dataclass
class _ArrayDimension:
    count: int


@dataclass
class _ArrayType:
    kind: str = "array"
    element_type_offset: int = 0
    dimensions: List[_ArrayDimension] = field(default_factory=list)


TypeNode = Union[
    _BaseType, _PointerType, _TypedefType, _ConstVolatileType,
    _EnumType, _StructType, _ArrayType
]


# ---------------------------------------------------------------------------
# Symbol entry (basic unit stored in cache)
# ---------------------------------------------------------------------------

@dataclass
class _SymEntry:
    address: int
    size: int


# ---------------------------------------------------------------------------
# Disk cache structure
# ---------------------------------------------------------------------------

_CACHE_VERSION = 11  # Incremented on format change to auto-invalidate old caches

@dataclass
class _Cache:
    version: int
    elf_mtime: float
    elf_size: int        # ELF file size, used alongside mtime for validation
    # Variable name -> (address, size)
    sym_map: Dict[str, _SymEntry]
    # Variable name -> CU offset (built on first info query)
    var_cu_map: Optional[Dict[str, int]] = None
    # Type name list (built on first list-types query)
    type_names: Optional[List[str]] = None
    # Type name -> CU offset (used by list-type search)
    type_cu_map: Optional[Dict[str, int]] = None
    # Line table [(address, filename, lineno), ...] (built on first pc2line)
    line_table: Optional[List[Tuple[int, str, int]]] = None
    # Function table [(low_pc, high_pc, name), ...] (built on first pc2line)
    func_table: Optional[List[Tuple[int, int, str]]] = None


# ---------------------------------------------------------------------------
# Main index class
# ---------------------------------------------------------------------------

class DwarfIndex:
    """
    ELF variable/type index.

    - sym_map  : symbol table index, name -> _SymEntry, loaded at startup (instant with cache)
    - types    : DWARF type dictionary, lazily populated (per-CU parsing)
    - variables: backward-compatible interface, same data as sym_map
    """

    def __init__(self, elf_path: str):
        self._elf_path = elf_path
        self._ptr_size = 4
        self._dwarf_info = None          # lazy-loaded
        self._elf_file_handle = None     # persistent file handle for DWARF

        # Tier 1: symbol table index (fast)
        self.sym_map: Dict[str, _SymEntry] = {}

        # Tier 2: DWARF type index (lazy-loaded per CU)
        self.types: Dict[int, TypeNode] = {}
        self._parsed_cu_offsets: set = set()  # already-parsed CUs

        # These three are populated in a single top-level scan, lazy-loaded:
        self._var_cu_map: Optional[Dict[str, int]] = None   # variable name -> CU offset
        self._type_cu_map: Optional[Dict[str, int]] = None  # type name -> CU offset
        self._type_names: Optional[List[str]] = None        # all type names

        # pc2line related, lazy-loaded
        self._line_table: Optional[List[Tuple[int, str, int]]] = None
        self._func_table: Optional[List[Tuple[int, int, str]]] = None

        self._load_symtab()

    # ------------------------------------------------------------------
    # Tier 1: Symbol table (with disk cache)
    # ------------------------------------------------------------------

    def _cache_path(self) -> str:
        return self._elf_path + ".idx"

    def _cache_valid(self) -> bool:
        cp = self._cache_path()
        if not os.path.exists(cp):
            return False
        try:
            with open(cp, "rb") as f:
                cache: _Cache = pickle.load(f)
            if cache.version != _CACHE_VERSION:
                return False
            elf_mtime = os.path.getmtime(self._elf_path)
            elf_size = os.path.getsize(self._elf_path)
            mtime_ok = abs(cache.elf_mtime - elf_mtime) < 1.0
            size_ok = cache.elf_size == elf_size
            return mtime_ok and size_ok
        except Exception:
            return False

    def _load_cache(self) -> bool:
        try:
            with open(self._cache_path(), "rb") as f:
                cache: _Cache = pickle.load(f)
            self.sym_map = cache.sym_map
            if cache.var_cu_map is not None:
                self._var_cu_map = cache.var_cu_map
            if cache.type_cu_map is not None:
                self._type_cu_map = cache.type_cu_map
            if cache.type_names is not None:
                self._type_names = cache.type_names
            if cache.line_table is not None:
                self._line_table = cache.line_table
            if cache.func_table is not None:
                self._func_table = cache.func_table
            return True
        except Exception:
            return False

    def _save_cache(self):
        try:
            cache = _Cache(
                version=_CACHE_VERSION,
                elf_mtime=os.path.getmtime(self._elf_path),
                elf_size=os.path.getsize(self._elf_path),
                sym_map=self.sym_map,
                var_cu_map=self._var_cu_map,
                type_cu_map=self._type_cu_map,
                type_names=self._type_names,
                line_table=self._line_table,
                func_table=self._func_table,
            )
            with open(self._cache_path(), "wb") as f:
                pickle.dump(cache, f, protocol=4)
        except Exception:
            pass  # Cache write failure is non-fatal

    def _load_symtab(self):
        # Attempt to load from cache
        if self._cache_valid() and self._load_cache():
            return

        from .progress import Progress
        with Progress("Building symbol table index"):
            with open(self._elf_path, "rb") as f:
                elf = ELFFile(f)
                self._ptr_size = 8 if elf.elfclass == 64 else 4

                if not elf.has_dwarf_info():
                    raise ValueError(
                        f"{self._elf_path} has no DWARF info; compile with -g."
                    )

                symtab = elf.get_section_by_name(".symtab")
                if symtab is None:
                    raise ValueError(
                        f"{self._elf_path} has no symbol table (.symtab)."
                        "It may have been stripped; cannot resolve variable addresses."
                    )

                for sym in symtab.iter_symbols():
                    if (sym.name
                            and sym.entry.st_info.type == "STT_OBJECT"
                            and sym.entry.st_value != 0):
                        self.sym_map[sym.name] = _SymEntry(
                            address=sym.entry.st_value,
                            size=sym.entry.st_size,
                        )

        with Progress("Writing cache"):
            self._save_cache()

    # ------------------------------------------------------------------
    # Tier 2: DWARF lazy loading
    # ------------------------------------------------------------------

    def _ensure_dwarf(self):
        """Ensure DWARF is opened (persistent file handle for subsequent CU parsing)"""
        if self._dwarf_info is not None:
            return
        self._elf_file_handle = open(self._elf_path, "rb")
        elf = ELFFile(self._elf_file_handle)
        self._ptr_size = 8 if elf.elfclass == 64 else 4
        self._dwarf_info = elf.get_dwarf_info()

    def _ensure_top_level_scan(self):
        """
        Scan top-level direct-child DIEs of all CUs in one pass, building:
          _var_cu_map  : variable name -> CU offset
          _type_cu_map : type name -> CU offset
          _type_names  : all type names (deduplicated & sorted)
        Results are written to cache for fast subsequent reads.
        """
        if self._var_cu_map is not None:
            return  # already built (from cache or previous scan)

        from .progress import Progress
        self._ensure_dwarf()
        self._var_cu_map = {}
        self._type_cu_map = {}
        type_name_set: set = set()
        type_tags = {"DW_TAG_typedef", "DW_TAG_structure_type", "DW_TAG_union_type"}

        def remember_type(lookup_name: str, display_name: str):
            if lookup_name not in self._type_cu_map:
                self._type_cu_map[lookup_name] = cu_off
            type_name_set.add(display_name)

        with Progress("Scanning DWARF variables and type index"):
            for cu in self._dwarf_info.iter_CUs():
                cu_off = cu.cu_offset
                top = cu.get_top_DIE()
                for child in top.iter_children():
                    tag = child.tag
                    attr = child.attributes.get("DW_AT_name")
                    if not attr:
                        continue
                    name = attr.value
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")

                    if tag == "DW_TAG_variable":
                        if name not in self._var_cu_map:
                            self._var_cu_map[name] = cu_off

                    elif tag in type_tags:
                        if tag == "DW_TAG_typedef":
                            remember_type(name, name)
                        elif tag == "DW_TAG_structure_type":
                            remember_type(name, f"struct {name}")
                            remember_type(f"struct {name}", f"struct {name}")
                        elif tag == "DW_TAG_union_type":
                            remember_type(name, f"union {name}")
                            remember_type(f"union {name}", f"union {name}")

        self._type_names = sorted(type_name_set)
        with Progress("Writing cache"):
            self._save_cache()

    def collect_all_type_names(self) -> List[str]:
        """Return all type names (triggers scan or reads from cache)"""
        self._ensure_top_level_scan()
        return self._type_names or []

    def find_type_cu(self, type_name: str) -> Optional[int]:
        """Return the CU offset where the given type is defined"""
        self._ensure_top_level_scan()
        if not self._type_cu_map:
            return None

        names = [type_name]
        for prefix in ("struct ", "union "):
            if type_name.startswith(prefix):
                names.append(type_name[len(prefix):])
                break

        for name in names:
            cu_offset = self._type_cu_map.get(name)
            if cu_offset is not None:
                return cu_offset
        return None

    def parse_cu_for_var(self, var_name: str) -> Optional[int]:
        """
        Find the CU containing the variable, parse all type DIEs in that CU,
        and return the variable's type_die_offset (for member resolution).
        """
        self._ensure_top_level_scan()

        cu_offset = self._var_cu_map.get(var_name)
        if cu_offset is None:
            return None

        if cu_offset not in self._parsed_cu_offsets:
            self._parse_cu(cu_offset)

        # In the parsed CU, find the variable's type_die_offset
        self._ensure_dwarf()
        cu = self._dwarf_info.get_CU_at(cu_offset)
        top = cu.get_top_DIE()
        for child in top.iter_children():
            if child.tag != "DW_TAG_variable":
                continue
            attr = child.attributes.get("DW_AT_name")
            if not attr:
                continue
            name = attr.value
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            if name == var_name:
                return self._attr_ref(child, "DW_AT_type")
        return None

    def _parse_cu(self, cu_offset: int):
        """Parse all DIEs in a single CU, populating self.types"""
        if cu_offset in self._parsed_cu_offsets:
            return
        self._parsed_cu_offsets.add(cu_offset)

        self._ensure_dwarf()
        cu = self._dwarf_info.get_CU_at(cu_offset)
        for die in cu.iter_DIEs():
            self._process_die(die)

    def _process_die(self, die):
        tag = die.tag
        if tag == "DW_TAG_base_type":
            self._parse_base_type(die)
        elif tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            self._parse_struct_type(die)
        elif tag == "DW_TAG_array_type":
            self._parse_array_type(die)
        elif tag == "DW_TAG_typedef":
            self._parse_typedef(die)
        elif tag in ("DW_TAG_const_type", "DW_TAG_volatile_type",
                     "DW_TAG_restrict_type"):
            self._parse_cv_type(die)
        elif tag == "DW_TAG_pointer_type":
            self._parse_pointer_type(die)
        elif tag == "DW_TAG_enumeration_type":
            self._parse_enum_type(die)

    # ------------------------------------------------------------------
    # Type DIE parsing
    # ------------------------------------------------------------------

    def _parse_base_type(self, die):
        name = self._attr_str(die, "DW_AT_name") or "<base>"
        size = self._attr_int(die, "DW_AT_byte_size") or 0
        self.types[die.offset] = _BaseType(name=name, size=size)

    def _parse_pointer_type(self, die):
        target = self._attr_ref(die, "DW_AT_type")
        size = self._attr_int(die, "DW_AT_byte_size") or self._ptr_size
        self.types[die.offset] = _PointerType(size=size, target_offset=target)

    def _parse_typedef(self, die):
        name = self._attr_str(die, "DW_AT_name") or ""
        target = self._attr_ref(die, "DW_AT_type")
        self.types[die.offset] = _TypedefType(name=name, target_offset=target)

    def _parse_cv_type(self, die):
        target = self._attr_ref(die, "DW_AT_type")
        self.types[die.offset] = _ConstVolatileType(target_offset=target)

    def _parse_enum_type(self, die):
        name = self._attr_str(die, "DW_AT_name") or "<anonymous>"
        size = self._attr_int(die, "DW_AT_byte_size") or 4
        self.types[die.offset] = _EnumType(name=name, size=size)

    def _parse_struct_type(self, die):
        name = self._attr_str(die, "DW_AT_name") or "<anonymous>"
        size = self._attr_int(die, "DW_AT_byte_size") or 0
        is_union = (die.tag == "DW_TAG_union_type")

        members: List[_StructMember] = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            m_name = self._attr_str(child, "DW_AT_name") or ""
            m_type = self._attr_ref(child, "DW_AT_type")
            m_offset = self._parse_member_offset(child)
            if m_type is not None:
                members.append(_StructMember(
                    name=m_name,
                    byte_offset=m_offset,
                    type_die_offset=m_type,
                ))

        self.types[die.offset] = _StructType(
            name=name, size=size, is_union=is_union, members=members
        )

    def _parse_member_offset(self, die) -> int:
        if "DW_AT_data_member_location" not in die.attributes:
            return 0
        attr = die.attributes["DW_AT_data_member_location"]
        val = attr.value
        if isinstance(val, int):
            return val
        if isinstance(val, (bytes, bytearray, list)):
            raw = bytes(val) if not isinstance(val, bytes) else val
            if len(raw) >= 2 and raw[0] == 0x23:  # DW_OP_plus_uconst
                return self._decode_uleb128(raw, 1)[0]
            if len(raw) >= 2 and raw[0] == 0x10:  # DW_OP_constu
                return self._decode_uleb128(raw, 1)[0]
        return 0

    def _parse_array_type(self, die):
        elem_type = self._attr_ref(die, "DW_AT_type")
        dimensions: List[_ArrayDimension] = []
        for child in die.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                count = -1
                if "DW_AT_count" in child.attributes:
                    count = self._attr_int(child, "DW_AT_count") or -1
                elif "DW_AT_upper_bound" in child.attributes:
                    ub = self._attr_int(child, "DW_AT_upper_bound")
                    if ub is not None:
                        count = ub + 1
                dimensions.append(_ArrayDimension(count=count))
        self.types[die.offset] = _ArrayType(
            element_type_offset=elem_type or 0,
            dimensions=dimensions,
        )

    # ------------------------------------------------------------------
    # Backward compatibility: variables property (derived from sym_map)
    # ------------------------------------------------------------------

    @property
    def variables(self):
        """Backward-compatible variable dictionary (_VarInfo-style)"""
        return _SymMapAdapter(self.sym_map)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _attr_str(self, die, attr_name: str) -> Optional[str]:
        if attr_name not in die.attributes:
            return None
        val = die.attributes[attr_name].value
        if isinstance(val, bytes):
            return val.decode("utf-8", errors="replace")
        return str(val)

    def _attr_int(self, die, attr_name: str) -> Optional[int]:
        if attr_name not in die.attributes:
            return None
        val = die.attributes[attr_name].value
        return val if isinstance(val, int) else None

    def _attr_ref(self, die, attr_name: str) -> Optional[int]:
        """
        Return the absolute file offset for a reference attribute.
        DW_FORM_ref1/2/4/8/udata are relative to the CU start; add cu_offset.
        DW_FORM_ref_addr is already an absolute offset.
        """
        if attr_name not in die.attributes:
            return None
        attr = die.attributes[attr_name]
        val = attr.value
        if attr.form in ("DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4",
                         "DW_FORM_ref8", "DW_FORM_ref_udata"):
            # Relative CU offset → add CU file-start position
            cu_offset = die.cu.cu_offset
            return cu_offset + val
        if attr.form == "DW_FORM_ref_addr":
            # Already absolute offset
            return val
        return None

    @staticmethod
    def _decode_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
        result, shift = 0, 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset

    def get_line_resolver(self):
        """
        Return a LineResolver instance.
        On first call, builds line & function tables (slow);
        subsequent calls restore from cache (instant).
        """
        from .line_resolver import build_line_table, build_func_table, LineResolver

        if self._line_table is None or self._func_table is None:
            from .progress import Progress
            with Progress("Parsing line table (.debug_line)"):
                self._line_table = build_line_table(self._elf_path)
            with Progress("Building function address index"):
                self._func_table = build_func_table(self._elf_path)
            with Progress("Writing cache"):
                self._save_cache()

        return LineResolver(self._line_table, self._func_table)

    def __del__(self):
        if self._elf_file_handle:
            try:
                self._elf_file_handle.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Compatibility adapter (so type_resolver's index.variables[name] still works)
# ---------------------------------------------------------------------------

class _FakeVarInfo:
    """Simulates the old _VarInfo, constructed from sym_map entries"""
    def __init__(self, name: str, entry: _SymEntry):
        self.name = name
        self.address = entry.address
        self.size = entry.size
        self.type_die_offset = None  # resolved via parse_cu_for_var when needed
        self.cu_offset = 0


class _SymMapAdapter:
    """Makes sym_map behave like dict[str, _VarInfo]"""
    def __init__(self, sym_map: Dict[str, _SymEntry]):
        self._m = sym_map

    def get(self, name, default=None):
        e = self._m.get(name)
        return _FakeVarInfo(name, e) if e else default

    def __contains__(self, name):
        return name in self._m

    def __getitem__(self, name):
        return _FakeVarInfo(name, self._m[name])

    def items(self):
        for name, e in self._m.items():
            yield name, _FakeVarInfo(name, e)

    def keys(self):
        return self._m.keys()

    def __len__(self):
        return len(self._m)

    def __iter__(self):
        return iter(self._m)
