// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check switch-table recovery in an auto-analysed tests/fixtures/jump-table.py image.

import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000JumpTableTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Instruction dispatch = getInstructionAt(toAddr(0x1014L));
		Set<Address> targets = new TreeSet<>();
		for (Reference ref : dispatch.getReferencesFrom()) {
			if (ref.getReferenceType().isFlow()) targets.add(ref.getToAddress());
		}
		Set<Address> expected = new TreeSet<>();
		for (long c : new long[] { 0x1020L, 0x1040L, 0x1060L }) expected.add(toAddr(c));
		if (!targets.equals(expected)) {
			throw new AssertionError("dispatch targets " + targets + ", expected " + expected);
		}
		Function function = getFunctionAt(toAddr(0x1000L));
		for (Address c : expected) {
			if (!function.getBody().contains(c)) throw new AssertionError(c + " not in the switch's function");
		}
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
		String c = result.getDecompiledFunction() == null ? "" : result.getDecompiledFunction().getC();
		if (!c.contains("switch") || c.contains("Could not recover jumptable")) {
			throw new AssertionError("decompiler did not use the switch:\n" + c);
		}
		// The table set up before a jump into the dispatch tail; the [B0] write in the jump's
		// delay slots belongs to the default path and must not replace the base.
		disassemble(toAddr(0x1200L));
		Set<Address> viaJump = new TreeSet<>(c6000.C6000JumpTableAnalyzer.switchTargets(
			currentProgram, getInstructionAt(toAddr(0x1248L))));
		Set<Address> expectedViaJump = new TreeSet<>();
		for (long t : new long[] { 0x1260L, 0x1280L, 0x12a0L }) expectedViaJump.add(toAddr(t));
		if (!viaJump.equals(expectedViaJump)) {
			throw new AssertionError("dispatch through a jump " + viaJump + ", expected " + expectedViaJump);
		}
		println("C6000_JUMP_TABLE_OK");
	}
}
