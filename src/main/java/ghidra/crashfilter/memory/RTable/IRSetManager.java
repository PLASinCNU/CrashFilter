package ghidra.crashfilter.memory.RTable;

import java.util.*;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.crashfilter.BinNavi.mono.InstructionGraph;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.TempReg;
import ghidra.crashfilter.memory.Val;
import ghidra.crashfilter.memory.env.Env;
import ghidra.crashfilter.memory.interfaces.IALoc;
import ghidra.crashfilter.memory.interfaces.IRegister;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.mloc.MFactoryHelper;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.crashfilter.memory.mloc.StructuredMLoc;
import ghidra.crashfilter.memory.mloc.Symbol_Bottom;
import ghidra.crashfilter.memory.mloc.Symbol_Top;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterManager;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public class IRSetManager { // singleton

	RTable rTable = null;

	private ILatticeGraph<InstructionGraphNode> instGraph;
	private Program prog;
	private Env env;
	// private Function func;
	private boolean callStackFlag = false;

	public void setEnv(Env env) {
		this.env = env;
	}

	private IRSetManager(RTable rt) {

		if (rt == null) {
			rTable = new RTable();
		} else {
			rTable = rt;
		}
		env = null;
	}

	private IRSetManager(Program prog) {
		this.prog = prog;
		rTable = new RTable();
		initFirst();
	}

	public RTable initFirst() {
		IRegister init_esp = null;
		StructuredMLoc init_stack = null;
		IRegister init_ebp = null;
		StructuredMLoc init_oldebp = null;
		IRegister init_heap = null;

		Set<IValue> value = new HashSet<IValue>();

		try {
			// init esp-> stack0
			init_esp = ActualReg.getActualReg("RSP");
			init_stack = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("stack")).c2(new Val(4)).build();

			value.add(init_stack);
			putElements(init_esp, value);

			value = new HashSet<IValue>();
			// init ebp-> old ebp
			init_ebp = ActualReg.getActualReg("RBP");
			init_oldebp = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("oldebp")).c2(new Val(0))
					.build();
			value.add(init_oldebp);
			putElements(init_ebp, value);

			// for arm
			ActualReg init_SP = new ActualReg("SP");
			StructuredMLoc init_stack_0 = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("stack"))
					.c2(new Val(0)).build();
			value.add(init_stack_0);
			putElements(init_SP, value);

			ActualReg init_LR = new ActualReg("LR");
			StructuredMLoc retAddr = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("retAddr"))
					.c2(new Val(0)).build();
			value.add(retAddr);
			putElements(init_LR, value);

			// for heap
			value = new HashSet<IValue>();
			init_heap = new ActualReg("heap");
			putElements(init_heap, value);

		} catch (MLocException e) {
			e.printStackTrace();
		}
		return rTable;
	}

	public RTable initEax2Heap() throws MLocException {

		IRegister eax = ActualReg.getActualReg("RAX");
		Set<IValue> vs = new HashSet<IValue>();
		vs.add(new ActualReg("heap"));

		putElements(eax, vs);

		return rTable;
	}

//	public RTable init() throws MLocException {
//		Set<IValue> value = new HashSet<IValue>();
//
//		// init esp-> stack0
//		initRegBottom("eax", new HashSet<IValue>());
//		initRegBottom("ebx", new HashSet<IValue>());
//		initRegBottom("ecx", new HashSet<IValue>());
//		initRegBottom("edx", new HashSet<IValue>());
//		initRegBottom("edi", new HashSet<IValue>());
//		initRegBottom("esi", new HashSet<IValue>());
//		initRegBottom("ZF", new HashSet<IValue>());
//		initRegBottom("OF", new HashSet<IValue>());
//		initRegBottom("CF", new HashSet<IValue>());
//		initRegBottom("SF", new HashSet<IValue>());
//
//		// for temp reg
//		for (int i = 0; i < 20; i++) {
//			initRegBottom("t" + i, value);
//		}
//
//		// for arm
//		initRegBottom("C", new HashSet<IValue>());
//		initRegBottom("N", new HashSet<IValue>());
//		initRegBottom("V", new HashSet<IValue>());
//		for (int i = 0; i < 16; i++) {
//			initRegBottom("R" + i, new HashSet<IValue>());
//		}
//		return rTable;
//	}

	void initRegBottom(String str, Set<IValue> value) {
		IRegister init_reg = null;
		Symbol_Bottom init_value = null;

		init_reg = MFactoryHelper.newIRegister(str);
		init_value = Symbol_Bottom.getSymbolBottom();

		value.add(init_value);
		putElements(init_reg, value);
	}

	static IRSetManager IRMGR = null;

	public static IRSetManager getIRSetManager(Program prog) {
		if (IRMGR != null)
			return IRMGR;
		IRMGR = new IRSetManager(prog);
		return IRMGR;
	}

	public void setRTable(RTable rt) {
		this.rTable = rt;
	}

	public RTable getRTable() {
		return this.rTable;
	}

	public void setGraph(Function curReilFunc) {
		instGraph = InstructionGraph.create(curReilFunc);
	}

	public void oneReilInst(PcodeOp inst) throws MLocException {

		// rTable = rt;

		switch (inst.getOpcode()) {
		case PcodeOp.PTRADD:
		case PcodeOp.INT_ADD: // addition
			addOperation(inst);
			break;
		case PcodeOp.INT_AND: // binary and
			andOperation(inst);
			break;
		case PcodeOp.INT_RIGHT:
		case PcodeOp.INT_LEFT: // binary shift
			bshOperation(inst);
			break;
		case PcodeOp.INT_SDIV:
		case PcodeOp.INT_DIV: // unsigned division
			divOperation(inst);
			break;
		case PcodeOp.CBRANCH:
		case PcodeOp.BRANCHIND:
		case PcodeOp.BRANCH:
			break;
		case PcodeOp.LOAD:
			ldmOperation(inst);
			break;
		case PcodeOp.INT_SREM:
		case PcodeOp.INT_REM:
			modOperation(inst);
			break;
		case PcodeOp.INT_MULT: // unsigned multiplication
			mulOperation(inst);
			break;
		case PcodeOp.UNIMPLEMENTED: // no operation
			break;
		case PcodeOp.INT_OR: // bitwise Or
			orOperation(inst);
			break;
		case PcodeOp.STORE: // store to memory
			stmOperation(inst);
			break;
		case PcodeOp.COPY: // store to register
			strOperation(inst);
			break;
		case PcodeOp.PTRSUB:
		case PcodeOp.INT_SUB: // subtract
			subOperation(inst);
			break;
		case PcodeOp.INT_XOR:
			xorOperation(inst);
			break;
		default: // 필요한 명령어만 처리 또는 차후에 구현
			break;
		}

	}

	public void runValueAnalysis() {
		// LogConsole.log("---------Start-----------\n");
		for (InstructionGraphNode inst : instGraph.getNodes()) {
			Address addr = inst.getPcode().getSeqnum().getTarget();
			PseudoDisassembler pdis = new PseudoDisassembler(prog);
			PseudoInstruction psi = null;
			try {
				psi = pdis.disassemble(addr);
			} catch (InsufficientBytesException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (UnknownInstructionException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (UnknownContextException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			if (inst.getPcode().getSeqnum().getTime() == psi.getPcode().length - 1) {
				clearCallStack(inst);
			}

			try {
				oneReilInst(inst.getPcode());
			} catch (MLocException e) {
				e.printStackTrace();
			}

			// rTable.printRTable();
			// env.printEnv();
			// LogConsole.log("--------------------\n");
		}

		deleteTempRegster(rTable);

		// LogConsole.log("-----------end---------\n");
	}

	private void deleteTempRegster(RTable rt) {
		// LogConsole.log("-----------------------delete temp start\n");
		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IRegister> keyset = rt.keySet();
		for (IRegister key : keyset) {
			if (key instanceof TempReg) {
				toBeRemoved.add(key);
			}
		}
		for (IALoc key : toBeRemoved) {
			rt.remove(key);
		}

// 		LogConsole.log("-----------------------delete temp end\n");
	}

	private void bshOperation(PcodeOp inst) throws MLocException {
		// If the second operand is positive, the shift is a left-shift.
		// If the second operand is negative, the shift is a right-shift.
//		if (op2.getValue().equals("0")) {
//			strOperation(op1, op2, op3);
//			return;
//		}
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();
		

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					Val op1Val = (Val) op1loc;
					Val op2Val = (Val) op1loc;
					long op1v = op1Val.getValue();
					long op2v = op2Val.getValue();
					if (inst.getOpcode() == PcodeOp.INT_RIGHT)
						value.add(shr(op1v, op2v));
					else
						value.add(shl(op1v, op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);

	}

	private Val shl(long op1v, long op2v) {
		return new Val(op1v << op2v);
	}

	private Val shr(long op1v, long op2v) {
		return new Val(op1v >> op2v);
	}

	private void strOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		putElements(op3reg, op1locs);
	}

	private void stmOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(1));
		Set<IValue> op3locs = opInit(inst.getInput(2));
		Set<IValue> value = new HashSet<IValue>();

		for (IValue val : op3locs) {
			if (val instanceof IRegister) {
				// MLoc -HG
				IRegister key = (IRegister) val;
				//
				this.putElements(key, op1locs);
			}
			if (val instanceof StructuredMLoc) {
				if (this.env == null) {
					// LogConsole.log("err : IRSetmanager.java - stmOperation() : env is null !!
					// \n");
				}
				StructuredMLoc key = (StructuredMLoc) val;
				///
				this.env.putElements(key, op1locs);
			}
		}
	}

	private void ldmOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1loc = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> loadedDatas = new HashSet<IValue>();

		for (IValue val : op1loc) {
			Set<IValue> regVal = new HashSet<IValue>();
			if (val instanceof IRegister) {
				IRegister reg = (IRegister) val;
				Set<IValue> data = this.getElements(reg);
				loadedDatas.addAll(data);
			} else if (val instanceof StructuredMLoc) {
				StructuredMLoc memoryLocation = (StructuredMLoc) val;
				if (env.containsKey(memoryLocation)) {
					Set<IValue> data = env.get(memoryLocation);
					if (data == null) {
						data.add(Symbol_Bottom.getSymbolBottom());
					}
					loadedDatas.addAll(data);
				} else {

				}
			}

		}
		
		this.putElements(op3reg, loadedDatas);
	}

	private void andOperation(PcodeOp inst) throws MLocException {
		/*
		 * todo if(op2.getValue().equals("4294967296")) { strOperation(op1,op2,op3);
		 * return; } if(op2.getValue().equals("4294967296")) {
		 * strOperation(op1,op2,op3); return; }
		 */
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					Val op1Val = (Val) op1loc;
					Val op2Val = (Val) op1loc;
					long op1v = op1Val.getValue();
					long op2v = op2Val.getValue();
					value.add(new Val(op1v & op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
	}

	private void orOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					Val op1Val = (Val) op1loc;
					Val op2Val = (Val) op1loc;
					long op1v = op1Val.getValue();
					long op2v = op2Val.getValue();
					value.add(new Val(op1v | op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
	}

	private void xorOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					Val op1Val = (Val) op1loc;
					Val op2Val = (Val) op1loc;
					long op1v = op1Val.getValue();
					long op2v = op2Val.getValue();
					value.add(new Val(op1v ^ op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);

	}

	private void subOperation(PcodeOp inst) throws MLocException {

		Set<IValue> op1loc = opInit(inst.getInput(0));
		Set<IValue> op2loc = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();
		for (IValue o1 : op1loc) {
			for (IValue o2 : op2loc) {
				value.add(subNAddOperation_(o1, o2, "sub"));
			}
		}
		putElements(op3reg, value);

	}

	private void addOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1loc = opInit(inst.getInput(0));
		Set<IValue> op2loc = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();
		for (IValue o1 : op1loc) {
			for (IValue o2 : op2loc) {
				value.add(subNAddOperation_(o1, o2, "add"));
			}
		}
		putElements(op3reg, value);

	}

	private IValue subNAddOperation_(IValue op1loc, IValue op2loc, String operation) throws MLocException {
		int flag = 1;
		if (operation.equals("sub")) {
			flag = -1;
		}

		if (op1loc instanceof Symbol_Top) {
			return Symbol_Top.getSymbolTop();
		}
		if (op1loc instanceof Symbol_Bottom) {
			return Symbol_Top.getSymbolTop();
		}

		if ((op1loc instanceof StructuredMLoc) && (op2loc instanceof Val)) {

			StructuredMLoc tStruct = ((StructuredMLoc) op1loc).copy();
			long op2v = ((Val) op2loc).getValue() * flag;
			Val t = new Val(tStruct.getC2().getValue() + op2v);
			tStruct.setC2(t);

			return tStruct;
		} else if ((op1loc instanceof IRegister) && (op2loc instanceof Val)) {
			// reg +- const
			IRegister op1reg = (IRegister) op1loc;
			Val op2val = (Val) op2loc;
			op2val = new Val(op2val.getValue() * flag);
			StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder().reg2(op1reg).c2(op2val).build();
			return tStruct;
		} else if ((op1loc instanceof Val) && (op2loc instanceof IRegister)) {
			// const +- reg
			if (operation.equals("add")) {
				// const + reg == reg + const
				IRegister op2reg = (IRegister) op2loc;
				Val op1val = (Val) op1loc;
				StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder().reg2(op2reg).c2(op1val).build();
				return tStruct;
			} else {
				// const - reg -> T
				return Symbol_Top.getSymbolTop();
			}
		}

		else if ((op1loc instanceof Val) && (op2loc instanceof StructuredMLoc)) {
			if (operation.equals("add")) {
				StructuredMLoc tStruct = ((StructuredMLoc) op2loc).copy();
				long op1v = ((Val) op1loc).getValue() * flag;
				Val t = new Val(tStruct.getC2().getValue() + op1v);
				tStruct.setC2(t);
				return tStruct;
			} else {
				return Symbol_Top.getSymbolTop();
			}
		} else if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
			long op1v = ((Val) op1loc).getValue();
			long op2v = ((Val) op2loc).getValue();
			return new Val(op1v + op2v * flag);
		}
		return Symbol_Top.getSymbolTop();
	}

	private void divOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					long op1v = ((Val) op1loc).getValue();
					long op2v = ((Val) op2loc).getValue();
					value.add(new Val(op1v / op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);

	}

	private void modOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					long op1v = ((Val) op1loc).getValue();
					long op2v = ((Val) op2loc).getValue();
					value.add(new Val(op1v % op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);

	}

	private void mulOperation(PcodeOp inst) throws MLocException {
		Set<IValue> op1locs = opInit(inst.getInput(0));
		Set<IValue> op2locs = opInit(inst.getInput(1));
		IRegister op3reg = MFactoryHelper.newIRegister(inst.getOutput());
		Set<IValue> value = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if ((op1loc instanceof Val) && (op2loc instanceof Val)) {
					long op1v = ((Val) op1loc).getValue();
					long op2v = ((Val) op2loc).getValue();
					value.add(new Val(op1v * op2v));
				} else {
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
	}

	private void print(RTable rTable2) {
		for (IRegister reg : rTable2.keySet()) {
			// LogConsole.log("Key : "+reg+"\n");
			for (IValue value : rTable2.get(reg)) {
				// LogConsole.log("\tValue : " + value + "\n");
			}

		}
	}

	private Set<IValue> opInit(Varnode op) {

		Set<IValue> oploc = null;

		if (op.isUnique()) {
			// LogConsole.log("opinit : -tx \n");
			oploc = new HashSet<IValue>();
			oploc.add(Symbol_Top.getSymbolTop());
			return oploc;
		}

		if (op.isRegister()) {
			IRegister op1reg = MFactoryHelper.newIRegister(op);
			Set<IValue> op1mapping = getElements(op1reg);

			if (op1mapping == null) {
				oploc = new HashSet<IValue>();
				oploc.add(Symbol_Bottom.getSymbolBottom());
				return oploc;
			}
			oploc = op1mapping;

		} else if (op.isConstant()) {
			oploc = new HashSet<IValue>();
			oploc.add(Val.newVal(op));
		} else if (op.isAddress()){
			// op is global variable 
			// homework 
			oploc = new HashSet<IValue>();
			oploc.add(Val.newVal(op));
		} else {
			//error
		}
		return oploc;
	}

	private void putElement(IRegister key, IValue value) {
		Set<IValue> valueSet = new HashSet<IValue>();
		valueSet.add(value);
		rTable.put(key, valueSet);
	}

	private void putElements(IRegister key, Set<IValue> value) {
		GhidraConsolePrint.println("key : "+key.toString());
		GhidraConsolePrint.println("value : " + value.toString());
		if (rTable.containsKey(key)) {
			rTable.remove(key);
		}
		if (value == null)
			value = new HashSet<>();
		rTable.put(key, value);
	}

	private void addElement(IRegister key, IValue value) {
		Set<IValue> valueSet = rTable.get(key);
		if (valueSet == null) {
			valueSet = new HashSet<IValue>();
		}

		valueSet.add(value);

		putElements(key, valueSet);
	}

	private Set<IValue> getElements(IRegister key) {
		Set<IValue> valueSet = rTable.get(key);
		if (valueSet == null) {
			valueSet = new HashSet<IValue>();
		}

		return valueSet;
	}

	private void clearCallStack(InstructionGraphNode inst) {
		Address funcAddr = inst.getAddr();

		Instruction nativeInst = prog.getListing().getInstructionAt(funcAddr);

		if (callStackFlag) {
			clearCallStack_Ebp();
			callStackFlag = false;
		}

		if (nativeInst.getMnemonicString().equals("CALL")) {
			callStackFlag = true;
		}

	}

	private void clearCallStack_Ebp() {
		Set<IValue> values = rTable.get(new ActualReg("RSP"));
		Set<IValue> newValues = new HashSet<IValue>();
		for (IValue value : values) {
			if (value instanceof StructuredMLoc) {
				StructuredMLoc structuredValue = (StructuredMLoc) value;
				env.remove(structuredValue);
				Val ori = structuredValue.getC2();
				Val add4 = new Val(ori.getValue() + 4);

				StructuredMLoc newStructuredValue = structuredValue.copy();
				newStructuredValue.setC2(add4);
				newValues.add(newStructuredValue);
				// rTable.remove(new ActualReg("esp"));
				// rTable.put(new ActualReg("esp"), newValues);
			}
		}
		rTable.remove(new ActualReg("RSP"));
		rTable.put(new ActualReg("RSP"), newValues);
	}
}
