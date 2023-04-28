package ghidra.crashfilter.helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeResolver {

	public enum PcodeCase {
		STORE,
		LOAD,
		OTHER
	};

	public static List<Varnode> resolveReilInstructionSrc(InstructionGraphNode inst) {
		return resolvePcodeSrc(inst.getPcode());
	}

	public static List<Varnode> resolvePcodeSrc(PcodeOp pcode) {
		pcode.getOutput();
		List<Varnode> src = new ArrayList<Varnode>();
		switch (pcode.getOpcode()) {
		case PcodeOp.STORE:
			src.add(pcode.getInput(2));
			break;
		case PcodeOp.LOAD:
			src.add(pcode.getInput(1));
			break;
		default:
			for (int i = 0; i < pcode.getNumInputs(); i++) {
				Varnode input = pcode.getInput(i);
				if (!input.isConstant())
					src.add(input);
			}
			break;
		}
		return src;
	}

	public static List<Varnode> resolveReilInstructionDest(InstructionGraphNode inst) {
		PcodeOp pcode = inst.getPcode();
		return resolveReilInstructionDest(pcode);
	}

	public static List<Varnode> resolveReilInstructionDest(PcodeOp pcode) {
		List<Varnode> dest = new ArrayList<Varnode>();
		if (pcode.isAssignment()) {
			dest.add(pcode.getOutput());
		}
		if (pcode.getOpcode() == PcodeOp.STORE)
			dest.add(pcode.getInput(1));

		return dest;
	}

	public static boolean isDefinitionInstruction(InstructionGraphNode inst) {
		PcodeOp pcode = inst.getPcode();
		return isDefinitionInstruction(pcode);
	}

	public static boolean isDefinitionInstruction(PcodeOp pcode) {
		if (pcode.isAssignment())
			return true;
		if (pcode.getOpcode() == PcodeOp.STORE)
			return true;

		return false;
	}

	public static boolean isLoadToRegister(InstructionGraphNode inst) {

		if (inst.getPcode().getOpcode() == PcodeOp.LOAD) {
			return true;
		}

		return false;
	}

	public static boolean isStoreToMemory(InstructionGraphNode inst) {
		if (inst.getPcode().getOpcode() == PcodeOp.STORE) {
			return true;
		}
		return false;
	}

	public static boolean isLiteralDirectAccess(InstructionGraphNode inst) {
		if (isLoadToRegister(inst)) {
			if (inst.getPcode().getInput(1).isRegister()) {
				return false;
			}
			return true;
		} else if (isStoreToMemory(inst)) {
			if (inst.getPcode().getInput(1).isRegister()) {
				return false;
			}
			return true;
		}
		// In case of other instruction like ADD, it is impossible
		else
			return false;
	}

	public static boolean isRegisterIndirectAccess(InstructionGraphNode inst) {
		if (isLoadToRegister(inst)) {
			if (inst.getPcode().getInput(1).isRegister()) {
				return true;
			}
			return true;
		} else if (isStoreToMemory(inst)) {
			if (inst.getPcode().getInput(1).isRegister()) {
				return true;
			}
			return true;
		}
		// In case of other instruction like ADD, it is impossible
		else
			return false;
	}

	public static boolean isSameDefinition(InstructionGraphNode def1, InstructionGraphNode def2) {
		// To do

		if (PcodeResolver.isStoreToMemory(def1)) {
			return false;
		} else if (PcodeResolver.isLoadToRegister(def1)) {
			if (PcodeResolver.isStoreToMemory(def2)) {
				return false;
			}
			for (Varnode dest1 : resolveReilInstructionDest(def1)) {
				for (Varnode dest2 : resolveReilInstructionDest(def2)) {
					return dest1.equals(dest2);
				}
			}
		}
		// In case of arithmetic
		else {
			if (PcodeResolver.isStoreToMemory(def2)) {
				return false;
			}
			for (Varnode dest1 : resolveReilInstructionDest(def1)) {
				for (Varnode dest2 : resolveReilInstructionDest(def2)) {
					return dest1.equals(dest2);
				}
			}
		}
		return false;
	}

	public static PcodeCase getKindInst(InstructionGraphNode use) {
		// TODO Auto-generated method stub
		PcodeOp pcode = use.getPcode();
		if (pcode.getOpcode() == PcodeOp.STORE)
			return PcodeCase.STORE;
		if (pcode.getOpcode() == PcodeOp.LOAD)
			return PcodeCase.LOAD;

		return PcodeCase.OTHER;
	}
}
