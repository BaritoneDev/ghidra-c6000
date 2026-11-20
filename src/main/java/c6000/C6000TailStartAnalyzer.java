/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Start a function at the packet after a body's last unconditional transfer.
 *
 * Code reached only through a function pointer, such as a registered hook or a chain of
 * MVK/MVKH/B trampolines, has no call reference, so nothing starts a function there and the
 * previous function's body runs on into it: a 12-byte stub takes the size and callees of the
 * function after it, and only the first of eight 16-byte trampolines gets a function. After an
 * unpredicated return or tail branch and its delay slots, code that nothing in the same function
 * branches or falls into belongs to something else.
 */
public class C6000TailStartAnalyzer extends AbstractAnalyzer {
	private static final int MAX_PASSES = 16;

	public C6000TailStartAnalyzer() {
		super("C6000 Tail Starts",
			"Starts functions after a final return or tail branch when nothing flows into the next packet",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		int made = 0;
		// a function analyzer is handed the new functions' entry points: read their bodies
		AddressSet scope = new AddressSet();
		for (Function f : program.getFunctionManager().getFunctions(set, true)) scope.add(f.getBody());
		for (int pass = 0; pass < MAX_PASSES; pass++) {
			List<Address> starts = new ArrayList<>();
			for (Instruction branch : program.getListing().getInstructions(scope, true)) {
				monitor.checkCancelled();
				Address next = afterTransfer(program, branch);
				if (next != null && isTailStart(program, next) && !starts.contains(next)) {
					starts.add(next);
				}
			}
			int before = made;
			for (Address at : starts) {
				Function owner = program.getFunctionManager().getFunctionContaining(at);
				if (new CreateFunctionCmd(at).applyTo(program, monitor)) {
					made++;
					if (owner != null) CreateFunctionCmd.fixupFunctionBody(program, owner, monitor);
				}
			}
			if (made == before) break;
			scope = new AddressSet(program.getMemory().getExecuteSet());  // a new function may end in another tail
		}
		if (made > 0) log.appendMsg(getName(), "started " + made + " function(s)");
		return true;
	}

	/** The first address after an unpredicated transfer's delay slots that doesn't return to
	 * the next packet (a return, a jump or a tail call), or null. */
	static Address afterTransfer(Program program, Instruction branch) {
		String name = branch.getMnemonicString();
		if (name.startsWith("[") || name.startsWith("_[")) return null;
		String bare = name.startsWith("_") ? name.substring(1) : name;
		if (!(bare.startsWith("B.") || bare.startsWith("BNOP."))) return null;
		FlowType flow = branch.getFlowType();
		if (flow.isCall() && !flow.isTerminal() || flow.isConditional() ||
			!(flow.isJump() || flow.isTerminal())) return null;
		// a register branch counts only as a return or a known tail call: one through a register
		// nothing resolved may be a call that returns after its window (SPRUFE8B 4.2.6)
		if (branch.getRegister(0) != null && !flow.isTerminal()) return null;
		if (branch.isInDelaySlot()) return null;
		Listing listing = program.getListing();
		Address end = branch.getMaxAddress();
		int delay = branch.getPrototype().getDelaySlotByteCount();
		if (delay > 0) {
			end = end.add(delay);
		}
		else {
			// a window the delay-slot recovery didn't materialise, such as B B31 in a trampoline:
			// count the five delay cycles, a NOP n packet as n and any other packet as one
			// (SPRUFE8B 4.2.6)
			end = countDelayCycles(program, branch);
			if (end == null) return null;
		}
		Address next = end.next();
		// skip fetch-packet headers; a stub reached only through a pointer follows the transfer
		// directly. After padding (NOPs, undecoded bytes) the code is a block of the function
		// before, reached by a jump, or code nothing reaches: neither starts a function.
		while (next != null && listing.getCodeUnitAt(next) instanceof Instruction ins &&
			ins.getMnemonicString().equals("CPKT")) {
			next = ins.getMaxAddress().next();
		}
		if (next == null || listing.getInstructionAt(next) == null ||
			listing.getInstructionAt(next).getMnemonicString().equals("NOP")) return null;
		return next;
	}

	private static final int DELAY_CYCLES = 5;

	/** The last address of the branch's fifth delay cycle, or null if it can't be followed. */
	private static Address countDelayCycles(Program program, Instruction branch) {
		Listing listing = program.getListing();
		try {
			int cycles = 0;
			if (branch.getMnemonicString().contains("BNOP")) {
				cycles = C6000ExecutionPackets.bnopCount(program, branch);
			}
			Instruction cur = branch;
			while (C6000ExecutionPackets.parallelWithNext(program, cur)) {
				cur = listing.getInstructionAfter(cur.getMaxAddress());
				if (cur == null) return null;
			}
			while (cycles < DELAY_CYCLES) {
				Instruction first = nextInstruction(listing, cur.getMaxAddress());
				if (first == null) return null;
				cur = first;
				boolean single = !C6000ExecutionPackets.parallelWithNext(program, cur);
				while (C6000ExecutionPackets.parallelWithNext(program, cur)) {
					cur = listing.getInstructionAfter(cur.getMaxAddress());
					if (cur == null) return null;
				}
				int nop = single ? nopCycles(first) : 0;
				cycles += nop > 0 ? nop : 1;
			}
			return cur.getMaxAddress();
		}
		catch (Exception e) {
			return null;
		}
	}

	/** The next instruction, past fetch-packet headers. */
	private static Instruction nextInstruction(Listing listing, Address after) {
		Instruction ins = listing.getInstructionAfter(after);
		while (ins != null && ins.getMnemonicString().equals("CPKT")) {
			ins = listing.getInstructionAfter(ins.getMaxAddress());
		}
		return ins;
	}

	private static int nopCycles(Instruction ins) {
		String m = ins.getMnemonicString();
		if (!m.equals("NOP")) return 0;
		if (ins.getNumOperands() == 0) return 1;
		try {
			return Integer.decode(ins.getDefaultOperandRepresentation(0));
		}
		catch (NumberFormatException e) {
			return 1;
		}
	}

	private static boolean isTailStart(Program program, Address at) {
		MemoryBlock block = program.getMemory().getBlock(at);
		if (block == null || !block.isExecute()) return false;
		var functions = program.getFunctionManager();
		if (functions.getFunctionAt(at) != null) return false;
		Listing listing = program.getListing();
		// only code something already decoded: bytes nothing reaches after a final transfer are
		// often data shaped like code
		Instruction ins = listing.getInstructionAt(at);
		if (ins == null || ins.isInDelaySlot() || !reachesTransfer(program, at)) return false;
		for (Reference ref : program.getReferenceManager().getReferencesTo(at)) {
			// calls and pointers (a hook table, a constant loaded with MVK/MVKH) say nothing
			// against; a jump or fall-through makes it a block of the code it comes from
			if (!ref.getReferenceType().isCall() && ref.getReferenceType().isFlow()) return false;
		}
		return true;
	}

	private static final int MAX_STUB = 64;

	/** The code from at decodes up to an unpredicated branch of its own before it runs into
	 * another function's entry, defined data, bytes that don't decode or the end of memory.
	 * Bytes after a final transfer that nothing reaches are often data or padding; a function
	 * reached only through a pointer still ends in a transfer. */
	private static boolean reachesTransfer(Program program, Address at) {
		var pseudo = new PseudoDisassembler(program);
		Listing listing = program.getListing();
		Address a = at;
		for (int k = 0; k < MAX_STUB && a != null; k++) {
			if (k > 0 && program.getFunctionManager().getFunctionAt(a) != null) return false;
			if (listing.getDefinedDataContaining(a) != null) return false;
			Instruction ins;
			try {
				ins = pseudo.disassemble(a);
			}
			catch (Exception e) {
				return false;
			}
			if (ins == null) return false;
			String m = ins.getMnemonicString();
			if (m.startsWith("_")) m = m.substring(1);
			if (m.startsWith("B.") || m.startsWith("BNOP.")) return true;
			a = ins.getMaxAddress().next();
		}
		return false;
	}
}
