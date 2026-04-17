"""
cli.py — Command-line interface.

Usage:
  elf-inspector <elf_file> <expr>                     Query variable/member
  elf-inspector <elf_file> pc2line <addr> [addr ...]  Resolve PC addresses to source
  elf-inspector <elf_file> list-globals               List all global variables
  elf-inspector <elf_file> list-members <type>        List struct member layout
  elf-inspector <elf_file> list-types                 List all known type names
"""

from __future__ import annotations

import sys

from .inspector import ElfInspector


def _cmd_query(insp: ElfInspector, expr: str):
    """Unified query: auto-detects whether the expression is a primitive type or struct, outputs accordingly."""
    try:
        info = insp.get_info(expr)
    except (KeyError, TypeError, IndexError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if info.members:
        chain_str = _fmt_chain(info)
        print(f"[{info.type_name}]  {chain_str}  ({info.size} bytes)")
        print()
        _print_members_recursive(insp, info.members, info.address, indent=0)
    else:
        size_str = f"  ({info.type_name}, {info.size}B)" if info.type_name not in ("", "<unknown>") else ""
        print(f"0x{info.address:08x}{size_str}")
        if len(info.chain) > 1:
            print(f"  {_fmt_chain(info)}")


def _print_members_recursive(insp: ElfInspector, members, base_addr: int, indent: int,
                              ancestor_offsets: frozenset = frozenset()):
    """
    Recursively print struct members in a tree view with indentation.
    ancestor_offsets: type offsets already expanded on the current path,
                      used to detect genuine circular references,
                      does not prevent expansion of same-type members at different branches.
    """
    from .dwarf_parser import _StructType
    from .type_resolver import resolve_type, type_name_of, size_of

    prefix = "  " * indent
    max_name = max(len(m[0]) for m in members)

    for m_name, m_addr, m_size, m_type, m_type_off in members:
        offset = m_addr - base_addr

        if m_type_off in ancestor_offsets:
            print(f"{prefix}  {m_name:<{max_name}}  0x{m_addr:08x}  +{offset:<6}  {m_size:>4}B  {m_type} <circular>")
            continue

        sub_members = _expand_struct(insp, m_addr, m_type_off)

        if sub_members is not None:
            print(f"{prefix}  {m_name:<{max_name}}  0x{m_addr:08x}  +{offset:<6}  {m_size:>4}B  [{m_type}]")
            _print_members_recursive(
                insp, sub_members, m_addr, indent + 1,
                ancestor_offsets | {m_type_off}
            )
        else:
            print(f"{prefix}  {m_name:<{max_name}}  0x{m_addr:08x}  +{offset:<6}  {m_size:>4}B  {m_type}")


def _expand_struct(insp: ElfInspector, base_addr: int, type_die_offset: int):
    """If type_die_offset corresponds to a struct, return its member list; otherwise return None."""
    from .dwarf_parser import _StructType
    from .type_resolver import resolve_type, type_name_of, size_of

    if type_die_offset is None:
        return None
    try:
        node = resolve_type(type_die_offset, insp._index)
    except (KeyError, ValueError):
        return None

    if not isinstance(node, _StructType):
        return None

    members = []
    for m in sorted(node.members, key=lambda x: x.byte_offset):
        m_addr = base_addr + m.byte_offset
        m_tname = type_name_of(m.type_die_offset, insp._index)
        m_size = size_of(m.type_die_offset, insp._index)
        members.append((m.name, m_addr, m_size, m_tname, m.type_die_offset))
    return members


def _fmt_chain(info) -> str:
    parts = []
    for i, (name, addr) in enumerate(info.chain):
        if i == 0:
            parts.append(f"{name}(0x{addr:08x})")
        else:
            delta = addr - info.chain[i - 1][1]
            parts.append(f"{name}(+{delta})")
    return " -> ".join(parts)


def _cmd_list_globals(insp: ElfInspector, args):
    globals_ = insp.list_globals()
    if not globals_:
        print("(no global variables)")
        return

    max_name = max(len(g.name) for g in globals_)
    header = f"{'Name':<{max_name}}  {'Address':>10}  {'Size':>6}"
    print(header)
    print("-" * len(header))
    for g in globals_:
        print(f"{g.name:<{max_name}}  0x{g.address:08x}  {g.size:>5}B")
    print(f"\ntotal {len(globals_)} global variables")


def _cmd_list_members(insp: ElfInspector, args):
    try:
        members = insp.list_members(args.type_name)
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not members:
        print(f"(type {args.type_name!r} has no members)")
        return

    max_name = max(len(m.name) for m in members)
    max_type = max(len(m.type_name) for m in members)
    header = (
        f"{'Member':<{max_name}}  "
        f"{'Offset':>8}  "
        f"{'Size':>5}  "
        f"Type"
    )
    print(f"struct/union {args.type_name}:")
    print(header)
    print("-" * (len(header) + max_type))
    for m in members:
        print(
            f"{m.name:<{max_name}}  "
            f"+{m.offset:<7}  "
            f"{m.size:>4}B  "
            f"{m.type_name}"
        )


def _cmd_list_types(insp: ElfInspector, args):
    types = insp.list_types()
    if not types:
        print("(no type information)")
        return
    for t in types:
        print(t)
    print(f"\ntotal {len(types)} types")


def _cmd_pc2line(insp: ElfInspector, addrs: list):
    """pc2line: input one or more PC addresses, output source file, line number, function name."""
    parsed = []
    for a in addrs:
        try:
            parsed.append(int(a, 16) if a.startswith("0x") or a.startswith("0X")
                          else int(a, 0))
        except ValueError:
            print(f"Error: Cannot parse address {a!r}", file=sys.stderr)
            sys.exit(1)

    stack = insp.pc2line_stack(parsed)

    max_file_w = 0
    max_func_w = 0
    rows = []
    for addr, info in stack.frames:
        if info:
            loc   = f"{info.filename}:{info.lineno}"
            func  = info.func_name
        else:
            loc  = "?"
            func = "<no debug info>"
        rows.append((addr, loc, func))
        max_file_w = max(max_file_w, len(loc))
        max_func_w = max(max_func_w, len(func))

    for i, (addr, loc, func) in enumerate(rows):
        print(f"#{i:<3} 0x{addr:08x}  {loc:<{max_file_w}}  {func}")


_SUBCOMMANDS = {"list-globals", "list-members", "list-types", "pc2line"}

_HELP = """\
Usage:
  elf-inspector <elf_file> <expr>                     Query variable/member (auto-detect type)
  elf-inspector <elf_file> pc2line <addr> [addr ...]  Resolve PC addresses to source location
  elf-inspector <elf_file> list-globals               List all global variables
  elf-inspector <elf_file> list-members <type>        List struct members and offsets
  elf-inspector <elf_file> list-types                 List all known type names

Examples:
  elf-inspector fw.elf counter5msCore0                Query variable address
  elf-inspector fw.elf sample                         Query struct (expands members)
  elf-inspector fw.elf sample.payload._length         Deep member query
  elf-inspector fw.elf pc2line 0x80012344             Single PC address resolution
  elf-inspector fw.elf pc2line 0x80012344 0x80015678  Stack trace resolution
  elf-inspector fw.elf list-globals                   List all global variables
  elf-inspector fw.elf list-members UartConfig        List struct layout
"""


def main():
    args = sys.argv[1:]

    if len(args) == 0 or args[0] in ("-h", "--help"):
        print(_HELP)
        sys.exit(0)

    if len(args) < 2:
        print("Error: ELF file path and query expression required", file=sys.stderr)
        print(_HELP)
        sys.exit(1)

    elf_file = args[0]
    command = args[1]

    try:
        insp = ElfInspector(elf_file)
    except FileNotFoundError:
        print(f"Error: File not found: {elf_file}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if command == "list-globals":
        _cmd_list_globals(insp, None)

    elif command == "list-members":
        if len(args) < 3:
            print("Error: list-members requires a type name", file=sys.stderr)
            sys.exit(1)

        class _A:
            type_name = args[2]

        _cmd_list_members(insp, _A())

    elif command == "list-types":
        _cmd_list_types(insp, None)

    elif command == "pc2line":
        if len(args) < 3:
            print("Error: pc2line requires at least one address, e.g. 0x80012344", file=sys.stderr)
            sys.exit(1)
        _cmd_pc2line(insp, args[2:])

    else:
        # Everything else is treated as a variable/member expression
        _cmd_query(insp, command)


if __name__ == "__main__":
    main()
