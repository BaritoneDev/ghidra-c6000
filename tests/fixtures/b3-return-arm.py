#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an if/else whose arms are a call and a return through B3. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Words are encoded from
SPRUFE8B's opcode diagrams for MV p.375, B pp.151, 153, ADDKPC p.128 and NOP p.388, checked against GNU objdump;
no firmware bytes. The compiler's shape for "if (a) return; f(); return":

  1000  MV.L2     B3,B13          save the link
  1004  [!A0]B.S1 1100            the call arm
  1008  [A0]B.S2  B3              the return arm, in the call's window
  100c  ADDKPC.S2 1010,B3,4       the call's return address, in both windows
  1010  MV.L2     B13,B3 ; B.S2 B3 ; NOP 5
  1100  B.S2 B3 ; NOP 5           (callee)

C6000B3ReturnArmTest.java checks that 1004 is a call to 1100 and 1008 stays a
conditional return.
"""

from pathlib import Path
import struct
import sys


def b_s1(at, target):
    """B.S1 to target, relative to the fetch packet holding at."""
    return 0x10 | ((((target - (at & ~31)) >> 2) & 0x1FFFFF) << 7)


def addkpc(at, ret, count):
    """ADDKPC.S2 ret,B3,count, relative to the fetch packet holding at."""
    return 0x162 | (((ret - (at & ~31)) >> 2) << 16) | (count << 13) | (3 << 23)


B_B3, NOP5 = 0x362 | (3 << 18), 4 << 13
A0, NOT_A0 = 0xC0000000, 0xD0000000
WORDS = {
    0x1000: 13 << 23 | 3 << 18 | 0xFDA,     # MV B3,B13
    0x1004: NOT_A0 | b_s1(0x1004, 0x1100),
    0x1008: A0 | B_B3,
    0x100C: addkpc(0x100C, 0x1010, 4),
    0x1010: 3 << 23 | 13 << 18 | 0xFDA,     # MV B13,B3
    0x1014: B_B3,
    0x1018: NOP5,
    0x1100: B_B3,
    0x1104: NOP5,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x120)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
