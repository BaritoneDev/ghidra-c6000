// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check that the analysis languages address linearly, in a tests/fixtures/analysis-addressing.py image.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.Set;

public class C6000AnalysisAddressingTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		boolean analysis = Set.of("analysis", "c67x-analysis").contains(
			currentProgram.getLanguage().getLanguageDescription().getVariant());
		new DisassembleCommand(toAddr(0x1000L), null, false).applyTo(currentProgram, monitor);
		Instruction load = getInstructionAt(toAddr(0x1000L));
		if (load == null || !load.getMnemonicString().startsWith("LDW")) {
			throw new AssertionError("decoded as " + load);
		}
		Register amr = currentProgram.getRegister("AMR");
		boolean readsAmr = false;
		for (PcodeOp op : load.getPcode()) {
			for (Varnode in : op.getInputs()) {
				readsAmr |= in.isRegister() && in.getAddress().equals(amr.getAddress());
			}
		}
		if (readsAmr == analysis) {
			throw new AssertionError(load + (analysis ? " reads AMR in the analysis language"
				: " ignores AMR in the exact language"));
		}
		// A4 in circular mode with BK0 = 1, a 4-byte block: the exact address wraps within the
		// block, the analysis address is A4 + 4.
		EmulatorHelper emulator = new EmulatorHelper(currentProgram);
		try {
			emulator.writeRegister("AMR", 0x00010001L);
			emulator.writeRegister("A4", 0x2004L);
			emulator.writeMemoryValue(toAddr(0x2004L), 4, 0x11111111L);
			emulator.writeMemoryValue(toAddr(0x2008L), 4, 0x22222222L);
			emulator.getEmulator().setExecuteAddress(0x1000L);
			if (!emulator.step(monitor)) throw new AssertionError(emulator.getLastError());
			// the load's data lands in E5
			for (int k = 0; k < 6 && emulator.readRegister("A5").longValue() == 0; k++) emulator.step(monitor);
			long loaded = emulator.readRegister("A5").longValue() & 0xffffffffL;
			if ((loaded == 0x22222222L) != analysis) {
				throw new AssertionError("loaded " + Long.toHexString(loaded) + " in the " +
					currentProgram.getLanguage().getLanguageDescription().getVariant() + " language");
			}
		}
		finally {
			emulator.dispose();
		}
		println("C6000_ANALYSIS_ADDRESSING_OK");
	}
}
