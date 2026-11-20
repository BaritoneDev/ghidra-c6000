// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check an if/else of a call and a return through B3 in an auto-analysed
// tests/fixtures/b3-return-arm.py image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000B3ReturnArmTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Instruction call = getInstructionAt(toAddr(0x1004L)), ret = getInstructionAt(toAddr(0x1008L));
		boolean calls = false;
		if (call != null) {
			for (Reference ref : call.getReferencesFrom()) {
				calls |= ref.getReferenceType().isCall() && ref.getToAddress().getOffset() == 0x1100L;
			}
		}
		if (call == null || !call.getFlowType().isCall() || !calls) {
			throw new AssertionError("call arm at 1004: " + call + (call == null ? "" : " flow=" + call.getFlowType()));
		}
		// B B3 with B3 still the saved link returns; the ADDKPC in its window is the other arm's link
		if (ret == null || ret.getFlowType().isCall() || !ret.getFlowType().isTerminal()) {
			throw new AssertionError("return arm at 1008: " + ret + (ret == null ? "" : " flow=" + ret.getFlowType()));
		}
		println("C6000_B3_RETURN_ARM_OK");
	}
}
