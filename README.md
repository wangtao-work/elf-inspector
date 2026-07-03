# ELF Inspector

A DWARF-based ELF file inspection tool for MCU firmware development and debugging.

No source code or running firmware required — statically parse ELF files to retrieve variable physical addresses, struct memory layouts, and source file/line locations for PC addresses.

---

## Table of Contents

1. [Background & Motivation](#background--motivation)
2. [How It Works](#how-it-works)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Features](#features)
6. [Usage](#usage)
7. [Caching Mechanism](#caching-mechanism)
8. [Compiler & Architecture Support](#compiler--architecture-support)
9. [Known Limitations](#known-limitations)

---

## Background & Motivation

During MCU firmware debugging, engineers often need to:

- Find the physical address of a global variable or struct member for log printing or memory reads
- Reconstruct a call stack from PC register values after a crash, to pinpoint the exact source line

The compiler toolchain provides `nm`, `readelf`, and `addr2line`, but they have several shortcomings:

| Problem | Detail |
|---------|--------|
| Symbol table only has basic info | `nm` can only find global variable addresses, not struct member offsets |
| Struct members require manual calculation | Nested struct offsets must be accumulated by hand, error-prone |
| `addr2line` is toolchain-specific | ARM ELF requires `arm-none-eabi-addr2line`, TriCore requires its own, no universal tool |
| Raw text output | Hard to batch-process or integrate into automation scripts |

ELF Inspector is built on standard DWARF debugging information, compiler-independent and architecture-independent, solving all of the above.

---

## How It Works

### ELF File Structure

A firmware ELF compiled with `-g` contains the following key sections:

```
.symtab      — symbol table (variable/function names → address, size)
.debug_info  — DWARF debug info: type definitions, variable info
.debug_line  — line table (code address → source filename + line number)
.debug_abbrev — DWARF abbreviation table
.debug_str   — string pool
```

### DWARF Debug Information

DWARF is an international standard (ISO/IEC 15767), followed by all major compilers. Debug info is organized as a tree of DIEs (Debugging Information Entry):

```
Compilation Unit (corresponds to one .c file)
├── DW_TAG_base_type        — uint32_t, int, char ...
├── DW_TAG_typedef          — type alias
├── DW_TAG_structure_type   — struct definition
│   ├── DW_TAG_member       — member name, byte offset
│   └── DW_TAG_member       — ...
├── DW_TAG_array_type       — array type + dimensions
└── DW_TAG_variable         — global variable (with DW_AT_location = address)
```

### Variable Address Resolution

Given `g_config.uart.baud_rate`:

```
1. Symbol table → g_config base_address = 0x20001200
2. DWARF type tree → g_config type is struct Config
3. Find member "uart" in Config → offset +4
4. uart type is struct UartConfig
5. Find member "baud_rate" in UartConfig → offset +0
6. Final address = 0x20001200 + 4 + 0 = 0x20001204
```

### PC Address to Source Line Resolution

The `.debug_line` section holds a mapping table produced by DWARF's line number state machine:

```
Code address     Source file              Line
0x80012340  →    ../src/motor.c           : 42
0x80012348  →    ../src/motor.c           : 43
0x80012360  →    ../include/pid.h         : 18
```

A binary search finds the closest entry ≤ the given PC address. Function names come from `STT_FUNC` entries in `.symtab`.

### Two-Tier Acceleration Strategy

```
Tier 1 — Symbol Table Index (.symtab)
       Cold start ~2s, cached <0.2s
       Covers: variable addresses, function address ranges

Tier 2 — DWARF On-Demand Parsing
       First invocation ~15s (cache build), cached <0.5s
       Covers: struct member offsets, type info, line tables
```

---

## Requirements

- Python 3.8+
- pyelftools >= 0.29

ELF compilation requirements:
- Must contain DWARF debug info (compile with `-g`)
- Use `-O0` or `-Og` to avoid optimization of variables away
- Must not be stripped (symbol table required)

---

## Installation

### Install dependency

```bash
pip install pyelftools
```

### Install tool (optional, enables running from any directory)

```bash
cd path/to/elf_inspector
pip install -e .
```

After installation, `python -m elf_inspector` works from any directory.

---

## Features

### 1. Variable / Struct Member Address Query

```bash
python -m elf_inspector <elf_file> list-globals <expr>
```

Supported expression formats:

| Expression | Description |
|------------|-------------|
| `varname` | Global variable |
| `var.member` | Struct member |
| `var.a.b.c` | Multi-level nested member |
| `var[n]` | Array element |
| `var[n].member` | Array element's member |
| `var[m][n]` | Multi-dimensional array element |

Output behavior:
- **Primitive type**: prints address, type name, and size
- **Struct variable**: recursively expands all members in an indented tree view, showing address, offset, size, and type for each
- **Nested structs**: auto-expanded to any depth
- **Circular references**: detected and labeled `<circular>`, no infinite loops

### 2. PC Address Resolution (Call Stack Reconstruction)

```bash
python -m elf_inspector <elf_file> pc2line <addr1> [addr2] [addr3] ...
```

- Accepts one or more PC addresses (hex with `0x` prefix, or decimal)
- Outputs: full source file path, line number, function name for each address
- Outputs in input order, `#0` being the top of the stack
- Displays `<no debug info>` if no debug information is found

### 3. List All Global / Static Variables

```bash
python -m elf_inspector <elf_file> list-globals
```

Lists all global/static variables with name, address, and size, sorted alphabetically.
If an expression is provided after `list-globals`, it queries that variable/member instead.

### 4. List Struct / Union Type Layout

```bash
python -m elf_inspector <elf_file> list-type <TypeName>
```

Lists the total struct/union size and all members, including: member name, byte offset, size, and type name.
Supports both `typedef` aliases (`UartConfig`) and raw struct names (`struct UartConfig`).

### 5. List All Known Types

```bash
python -m elf_inspector <elf_file> list-types
```

Lists all `typedef`, `struct`, and `union` type names found in the ELF, useful for confirming type name spelling before querying.

---

## Usage

Show command usage and examples:

```bash
python -m elf_inspector firmware.elf help
python -m elf_inspector firmware.elf --help
```

`help`, `-help`, `--help`, and `-h` are accepted.

### Scenario 1: Query Global Variable Address

```bash
# 1. Simple variable
python -m elf_inspector firmware.elf list-globals counter5msCore0
# Output: 0xb00cd0d4  (long unsigned int, 4B)

# 2. Struct variable (auto-expands all members)
python -m elf_inspector firmware.elf list-globals sample
# Output:
# [ThroughputModule_DataType]  sample(0xb0097ec4)  (24 bytes)
#
#   count    0xb0097ec4  +0      8B  uint64_t
#   payload  0xb0097ecc  +8     16B  [dds_sequence_octet]
#     _maximum  0xb0097ecc  +0   4B  uint32_t
#     _length   0xb0097ed0  +4   4B  uint32_t
#     _buffer   0xb0097ed4  +8   4B  uint8_t*
#     _release  0xb0097ed8  +12  1B  _Bool

# 3. Nested member address
python -m elf_inspector firmware.elf list-globals sample.payload._length
# Output: 0xb0097ed0  (uint32_t, 4B)
#         sample(0xb0097ec4) -> .payload(+8) -> ._length(+4)

# 4. Array element
python -m elf_inspector firmware.elf list-globals g_buf[3]
```

### Scenario 2: MCU Crash Call Stack Reconstruction

Obtain the PC register values and call stack addresses from a serial log or debugger after a crash:

```bash
python -m elf_inspector firmware.elf pc2line \
    0x80300100 \
    0x803c0d20 \
    0x803c0d46 \
    0x803c0d2c

# Output:
# #0   0x80300100  src/platform/Ssw/Ifx_Ssw_CompilersGnuc.h:164  osTrap_0_Core0
# #1   0x803c0d20  src/Cpu0_Main.c:84                             core0_main
# #2   0x803c0d46  src/platform/Ssw/Ifx_Ssw_Infra.h:343          core0_main
# #3   0x803c0d2c  src/Cpu0_Main.c:99                             core0_main
```

Source files do not need to be present locally — path information is embedded in the ELF.

### Scenario 3: Query Struct Layout

If you don't know the type name, search first:

```bash
# List all types containing "Uart" (pipe through grep)
python -m elf_inspector firmware.elf list-types | grep -i uart

# View detailed struct layout
python -m elf_inspector firmware.elf list-type UartConfig
# Output:
# struct/union UartConfig  (16 bytes):
# Member      Offset     Size  Type
# ------------------------------------
# baud_rate  +0          4B  uint32_t
# parity     +4          1B  uint8_t
# stop_bits  +5          1B  uint8_t
# timeout_ms +6          2B  uint16_t
```

### Scenario 4: Batch Queries (Python API)

The tool provides a Python API for automation:

```python
from elf_inspector import ElfInspector

insp = ElfInspector("firmware.elf")

# Query address
addr = insp.get_address("g_config.uart.baud_rate")
print(hex(addr))  # 0x20001204

# Query full info
info = insp.get_info("sample.payload")
print(info.address, info.size, info.type_name)

# PC address resolution
stack = insp.pc2line_stack([0x80300100, 0x803c0d20, 0x803c0d46])
print(stack)

# List global variables
for g in insp.list_globals():
    print(f"{g.name:40s}  0x{g.address:08x}  {g.size}B")

# List struct members
for m in insp.list_members("UartConfig"):
    print(f"  +{m.offset:<4}  {m.name:20s}  {m.type_name}")
```

---

## Caching Mechanism

The tool automatically maintains a cache file `<elf_filename>.idx` alongside the ELF file to avoid repeated full scans.

### Cache Contents

| Content | Trigger | Build Time |
|---------|---------|------------|
| Symbol table index (variable addresses) | First load | ~2s |
| Top-level variable/type name map | First `info`/`list-types` query | ~15s |
| Line table + function table | First `pc2line` query | ~10s |

### Cache Invalidation

The cache validates both the ELF's **modification time (mtime)** and **file size**. It is automatically rebuilt when:

- The ELF is recompiled (mtime changes)
- The ELF file size changes
- The tool version updates (internal version bump)

No manual cache management required.

### Cold vs Warm Startup

| Operation | First (cold start) | Subsequent (warm start) |
|-----------|-------------------|------------------------|
| Variable address query | ~2s | ~0.2s |
| Struct expansion / `list-types` | ~17s | ~0.3s |
| `pc2line` | ~12s | ~0.5s |

During cold start, a progress indicator is displayed on stderr so the user knows work is in progress.

---

## Compiler & Architecture Support

Built on standard DWARF (2/3/4/5), the tool is compiler- and architecture-independent:

| Compiler | Support |
|----------|---------|
| GCC / arm-none-eabi-gcc | ✅ |
| HighTec GCC (TriCore) | ✅ |
| Tasking (TriCore) | ✅ |
| Green Hills (GHS) | ✅ |
| IAR | ✅ |
| LLVM / Clang | ✅ |

| Target Architecture | Support |
|---------------------|---------|
| ARM Cortex-M (32-bit) | ✅ |
| TriCore (Infineon) | ✅ |
| RISC-V (32/64-bit) | ✅ |
| x86 / x86_64 | ✅ |

No platform-specific tools required (no need for `arm-none-eabi-addr2line`, etc.) — just a standard Python environment.

---

## Known Limitations

| Limitation | Detail |
|------------|--------|
| Local variables | Addresses determined at runtime by the stack; no fixed physical address, not supported |
| Pointer dereferencing | Shows the pointer variable's own address only; cannot dereference (unknown at compile time) |
| Compiler optimization | `-O2` and above may optimize variables away; use `-O0 -g` or `-Og -g` |
| Stripped ELF | ELF files stripped of `.symtab` cannot be used for variable address queries |
| Address aliasing | Platforms like TriCore have cached/uncached address aliases; manual address translation required before input |
