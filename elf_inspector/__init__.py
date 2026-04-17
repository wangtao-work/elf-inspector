"""
elf_inspector — ELF/DWARF variable address resolver.

Quick start::

    from elf_inspector import ElfInspector

    insp = ElfInspector("firmware.elf")
    print(hex(insp.get_address("g_config.uart.baud_rate")))
    print(insp.get_info("g_buf[3]"))
"""

from .inspector import ElfInspector
from .dwarf_parser import AddressInfo, GlobalInfo, MemberInfo

__all__ = ["ElfInspector", "AddressInfo", "GlobalInfo", "MemberInfo"]
__version__ = "0.1.0"
