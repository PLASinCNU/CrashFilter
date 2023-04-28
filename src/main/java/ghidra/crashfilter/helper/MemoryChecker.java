package ghidra.crashfilter.helper;

import java.util.Set;

import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.MLocLatticeElement;
import ghidra.crashfilter.memory.env.Env;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.crashfilter.memory.mloc.StructuredMLoc;
import ghidra.program.model.pcode.PcodeOp;

public class MemoryChecker {
	private IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult;

	public void setMLocResult(IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult) {
		this.mLocResult = mLocResult;
	}

	public boolean differentMemoryCheckEnv(InstructionGraphNode inst_stm, InstructionGraphNode inst_ldm)
			throws MLocException {
		// �Լ��̸��� ���� ������ �ʿ� ����

		if (stackNHeapRelationCheck(inst_ldm, inst_stm)) {
			return true;
		}
		if (isFromStackMemoryEnv(inst_ldm) && isToStackMemoryEnv(inst_stm)) {
			return isDeffrentStack(inst_ldm, inst_stm);
		}

		if (isdiffrent(inst_stm, inst_ldm)) {
			return true;
		}
		return false;
	}

	private boolean stackNHeapRelationCheck(InstructionGraphNode inst_stm, InstructionGraphNode inst_ldm)
			throws MLocException {
		return (isFromStackMemoryEnv(inst_ldm) && isToHeapMemoryEnv(inst_stm))
				|| (isFromHeapMemoryEnv(inst_ldm) && isToStackMemoryEnv(inst_stm));
	}

	private boolean isdiffrent(InstructionGraphNode inst1, InstructionGraphNode inst2) throws MLocException {

		PcodeOp i1 = inst1.getPcode();
		PcodeOp i2 = inst2.getPcode();

		if ((i1.getOpcode() == PcodeOp.STORE && i1.getOpcode() == PcodeOp.LOAD)) {

			Set<IValue> valueSet1 = getIValueSetAbout(inst1);
			Set<IValue> valueSet2 = getIValueSetAbout(inst2);
			if (valueSet1 == null || valueSet2 == null) {
				// LogConsole.log("\n");
				return true;
			}
			for (IValue value1 : valueSet1) {
				for (IValue value2 : valueSet2) {
					if (value1 instanceof StructuredMLoc && value2 instanceof StructuredMLoc) {
						StructuredMLoc s1 = (StructuredMLoc) value1;
						StructuredMLoc s2 = (StructuredMLoc) value2;
						if (s1.getReg2().equals(s2.getReg2()) && (s1.getReg2().equals(ActualReg.getActualReg("RSP"))
								|| s1.getReg2().equals(ActualReg.STACK) || s1.getReg2().equals(ActualReg.getActualReg("SP")))) {
							if (s1.getC2().getValue() == s2.getC2().getValue()) {
								return false;
							}
						}
					}
				}
			}
			return true;
		}
		return false;
	}

	private boolean isDeffrentStack(InstructionGraphNode inst1, InstructionGraphNode inst2) throws MLocException {
		Set<IValue> valueSet1 = getIValueSetAbout(inst1);
		Set<IValue> valueSet2 = getIValueSetAbout(inst2);
		if (valueSet1 == null || valueSet2 == null) {
			return true;
		}

		for (IValue value1 : valueSet1) {
			for (IValue value2 : valueSet2) {
				if (value1 instanceof StructuredMLoc && value2 instanceof StructuredMLoc) {
					StructuredMLoc s1 = (StructuredMLoc) value1;
					StructuredMLoc s2 = (StructuredMLoc) value2;
					if (s1.getReg2().equals(new ActualReg("stack")) && s2.getReg2().equals(new ActualReg("stack"))) {
						// both structuredMLoc is stack.
						{
							return false;
						}
					}
					if (s1.getReg2().equals(new ActualReg("SP")) && s2.getReg2().equals(new ActualReg("SP"))) {
						// both structuredMLoc is stack.
						if (s1.getC2().getValue() == s2.getC2().getValue()) {
							return false;
						}
					}
					if (s1.getReg2().equals(new ActualReg("RSP")) && s2.getReg2().equals(new ActualReg("RSP"))) {
						// both structuredMLoc is stack.
						if (s1.getC2().getValue() == s2.getC2().getValue()) {
							return false;
						}
					}
				}
			}
		}
		return true;

	}

	private Set<IValue> getIValueSetAbout(InstructionGraphNode inst) throws MLocException {
		// ldm / stm �Լ� ����,
		MLocLatticeElement envLatticeElement = mLocResult.getState(inst);
		Env env = envLatticeElement.getEnv();
		PcodeOp reilInst = inst.getPcode();

		if (reilInst.getOpcode() == PcodeOp.LOAD) {
			StructuredMLoc loc = StructuredMLoc.newStructuredMLoc(reilInst.getInput(1));
			return env.get(loc);
		} else if (reilInst.getOpcode() == PcodeOp.STORE) {
			StructuredMLoc loc = StructuredMLoc.newStructuredMLoc(reilInst.getOutput());
			return env.get(loc);
		}

		return null;
	}

	private boolean isFromStackMemoryEnv(InstructionGraphNode inst) throws MLocException {
		PcodeOp reilInst = inst.getPcode();
		if (reilInst.getMnemonic() != "ldm") {
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory(reilInst.getInput(1).toString());
		if (v == null) {
			return false;
		}
		if (v.equals(new ActualReg("stack"))) {
			return true;
		}
		return false;
	}

	private boolean isFromHeapMemoryEnv(InstructionGraphNode inst) throws MLocException {
		PcodeOp reilInst = inst.getPcode();
		if (reilInst.getOpcode()==PcodeOp.LOAD) {
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory(reilInst.getInput(1).toString());
		if (v == null) {
			return false;
		}
		if (v.equals(new ActualReg("heap"))) {
			return true;
		}
		return false;
	}

	private boolean isToStackMemoryEnv(InstructionGraphNode inst) throws MLocException {
		PcodeOp reilInst = inst.getPcode();
		if (reilInst.getOpcode() == PcodeOp.STORE) {
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory(reilInst.getOutput().toString());
		if (v == null) {
			return false;
		}
		if (v.equals(new ActualReg("stack"))) {
			return true;
		}
		return false;
	}

	private boolean isToHeapMemoryEnv(InstructionGraphNode inst) throws MLocException {
		PcodeOp reilInst = inst.getPcode();
		if (reilInst.getMnemonic() != "stm") {
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory(reilInst.getOutput().toString());
		if (v == null) {
			return false;
		}
		if (v.equals(new ActualReg("heap"))) {
			return true;
		}
		return false;
	}

}
