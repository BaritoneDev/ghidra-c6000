#!/usr/bin/env python3
"""Build a TI-style switch dispatch image. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis:

  1000  MVK.S2  0x1100,B5         ; table base
  1004  MVKH.S2 0x0,B5
  1008  CMPLTU.L2 2,B4,B0         ; guard: index 0..2
  100c  LDW.D2T2 *+B5[B4],B4
  1010  NOP 4
  1014  B.S2 B4                   ; dispatch
  1018  NOP 5
  1020/1040/1060/1080  B.S2 B3 ; NOP 5   (cases 0-2, then an unrelated routine)
  1100  .word 0x1020, 0x1040, 0x1060, 0x1080

The fourth word is a valid code address past the guard bound, so
C6000JumpTableTest.java checks the dispatch gets exactly cases 0-2.
The CMPLTU and LDW words are firmware encodings with operands changed.

A second dispatch, left for the test to disassemble, sets its table up
before a jump into the dispatch tail; a guard-predicated write in the
jump's delay slots runs only on the default path:

  1200  MVK.S2  0x1300,B5
  1204  MVKH.S2 0x0,B5
  1208  CMPLTU.L2 2,B4,B0
  120c  B.S1 1240
  1210  [B0] MVK.S2 0x1234,B5
  1214  NOP 4
  1218  MVK.S2 0x77,B5 ; B.S2 B3 ; NOP 5     (another routine)
  1240  LDW.D2T2 *+B5[B4],B4 ; NOP 4 ; B.S2 B4 ; NOP 5
  1260/1280/12a0/12c0  B.S2 B3 ; NOP 5
  1300  .word 0x1260, 0x1280, 0x12a0, 0x12c0
"""

from pathlib import Path
import struct
import sys


def mvk(cst, reg):
    return 0x2A | ((cst & 0xFFFF) << 7) | (reg << 23)


def mvkh(cst, reg):
    return 0x6A | ((cst & 0xFFFF) << 7) | (reg << 23)


def nop(count):
    return (count - 1) << 13


B_B3 = 0x362 | (3 << 18)
CMPLTU = (0x0014EBDA & ~(0x1F << 13) & ~(0x1F << 18)) | (2 << 13) | (4 << 18)

WORDS = {
    0x1000: mvk(0x1100, 5),
    0x1004: mvkh(0, 5),
    0x1008: CMPLTU,
    0x100C: 0x02148AE6,                     # LDW.D2T2 *+B5[B4],B4
    0x1010: nop(4),
    0x1014: 0x362 | (4 << 18),              # B.S2 B4
    0x1018: nop(5),
}
for case in (0x1020, 0x1040, 0x1060, 0x1080):
    WORDS[case] = B_B3
    WORDS[case + 4] = nop(5)
for i, target in enumerate((0x1020, 0x1040, 0x1060, 0x1080)):
    WORDS[0x1100 + 4 * i] = target

WORDS.update({
    0x1200: mvk(0x1300, 5),
    0x1204: mvkh(0, 5),
    0x1208: CMPLTU,
    0x120C: 0x10 | (0x10 << 7),             # B.S1 1240
    0x1210: (1 << 29) | mvk(0x1234, 5),     # [B0]
    0x1214: nop(4),
    0x1218: mvk(0x77, 5),
    0x121C: B_B3,
    0x1220: nop(5),
    0x1240: 0x02148AE6,
    0x1244: nop(4),
    0x1248: 0x362 | (4 << 18),
    0x124C: nop(5),
})
for i, target in enumerate((0x1260, 0x1280, 0x12A0, 0x12C0)):
    WORDS[target] = B_B3
    WORDS[target + 4] = nop(5)
    WORDS[0x1300 + 4 * i] = target


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x320)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
