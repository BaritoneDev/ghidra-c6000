#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a load through a circular-capable base. Usage: IMAGE [be].

Load at 0x1000 without auto-analysis. Independent manual fields (SPRUFE8B
LDW p.300, 2.8.3), no firmware bytes:

  1000  LDW.D1T1 *+A4[1],A5
  1004  B.S2     B3
  1008  NOP      5

C6000AnalysisAddressingTest.java runs it with AMR selecting circular mode
for A4: the exact languages wrap the address, the analysis languages read
the linear one.
"""

from pathlib import Path
import struct
import sys

WORDS = [
    5 << 23 | 4 << 18 | 1 << 13 | 1 << 9 | 6 << 4 | 1 << 2,  # LDW *+A4[1],A5
    3 << 18 | 0x362,                                        # B B3
    4 << 13,                                                # NOP 5
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x20)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
