// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check function starts after final transfers in an auto-analysed tests/fixtures/tail-starts.py
// image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000TailStartsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		StringBuilder found = new StringBuilder();
		for (var f : currentProgram.getFunctionManager().getFunctions(true)) {
			found.append(' ').append(f.getEntryPoint()).append(':').append(f.getBody());
		}
		for (int k = 0; k < 8; k++) {
			Function f = getFunctionAt(toAddr(0x1000L + 16 * k));
			if (f == null || f.getBody().getNumAddresses() != 16) {
				throw new AssertionError("trampoline " + k + ": " + (f == null ? "no function" : f.getBody()) +
					"; functions:" + found);
			}
			long handler = 0x1200L + 64 * k;
			if (k == 7) {
				// a branch through a register it can't classify is no final transfer
				if (getFunctionAt(toAddr(handler + 8)) != null) {
					throw new AssertionError("function after B B4 at " + toAddr(handler + 8) + "; functions:" + found);
				}
				continue;
			}
			// the else-block after the handler's return is its own branch target
			Function h = getFunctionAt(toAddr(handler));
			if (h == null || getFunctionContaining(toAddr(handler + 0x20)) != h) {
				throw new AssertionError("handler " + k + " lost its else-block; functions:" + found);
			}
		}
		// the zero padding after the trampolines and between handlers starts nothing
		var padding = currentProgram.getFunctionManager().getFunctions(
			currentProgram.getAddressFactory().getAddressSet(toAddr(0x1080L), toAddr(0x11ffL)), true);
		if (padding.hasNext()) throw new AssertionError("function in padding; functions:" + found);
		for (int k = 0; k < 8; k++) {
			long gap = 0x1210L + 64 * k;
			if (getFunctionAt(toAddr(gap)) != null) throw new AssertionError("function at " + toAddr(gap) + "; functions:" + found);
		}
		println("C6000_TAIL_STARTS_OK");
	}
}
