#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a row of trampolines reached only through pointers. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Words are encoded from
SPRUFE8B's opcode diagrams for MVK p.381, MVKH p.383, B pp.151, 153 and NOP p.388; no firmware bytes. Eight
16-byte trampolines, each a tail branch to its own handler, then zero padding:

  1000 + 16k  MVK.S2  0x1200 + 64k,B31
  1004 + 16k  MVKH.S2 0x0,B31
  1008 + 16k  B.S2    B31
  100c + 16k  NOP     5

Each handler but the last has an else-block after its return, then zero padding:

  1200 + 64k  [A1]B.S1 1220 + 64k     1220 + 64k  MVK.S1 1,A4
  1204 + 64k  NOP     5               1224 + 64k  B.S2 B3
  1208 + 64k  B.S2    B3              1228 + 64k  NOP 5
  120c + 64k  NOP     5

The last handler (13c0) is B.S2 B4 ; NOP 5 with B4 unknown, then B.S2 B3 ;
NOP 5 at 13c8 that nothing reaches: the branch may be a call returning there,
so it starts no function.

Nothing branches to 1010, 1020, ...: a table of hooks would hold their
addresses. C6000TailStartsTest.java checks each trampoline is a function of
its own, 16 bytes long, that nothing after padding becomes one, and that each
handler's else-block (after padding, reached by a jump) stays in the handler.
"""

from pathlib import Path
import struct
import sys


def mvk(cst, reg):
    return 0x2A | ((cst & 0xFFFF) << 7) | (reg << 23)


def mvk_s1(cst, reg):
    return 0x28 | ((cst & 0xFFFF) << 7) | (reg << 23)


def b_s1(at, target):
    """B.S1 to target, relative to the fetch packet holding at."""
    return 0x10 | ((((target - (at & ~31)) >> 2) & 0x1FFFFF) << 7)


def mvkh(cst, reg):
    return 0x6A | ((cst & 0xFFFF) << 7) | (reg << 23)


B_B3 = 0x362 | (3 << 18)
B_B31 = 0x362 | (31 << 18)
B_B4 = 0x362 | (4 << 18)
NOP5 = 4 << 13
A1 = 0x80000000


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x400)
    for k in range(8):
        handler = 0x1200 + 64 * k
        for i, word in enumerate((mvk(handler, 31), mvkh(handler >> 16, 31), B_B31, NOP5)):
            struct.pack_into(endian + "I", image, 16 * k + 4 * i, word)
        words = {0: A1 | b_s1(handler, handler + 0x20), 4: NOP5, 8: B_B3, 0xC: NOP5,
                 0x20: mvk_s1(1, 4), 0x24: B_B3, 0x28: NOP5}
        if k == 7:
            # a branch through B4, whose target is unknown, then code nothing reaches
            words = {0: B_B4, 4: NOP5, 8: B_B3, 0xC: NOP5}
        for offset, word in words.items():
            struct.pack_into(endian + "I", image, handler + offset - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
