package ghidra.crashfilter.memory.env;

import java.util.*;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.TempReg;
import ghidra.crashfilter.memory.Val;
import ghidra.crashfilter.memory.RTable.RTable;
import ghidra.crashfilter.memory.interfaces.IALoc;
import ghidra.crashfilter.memory.interfaces.IRegister;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.mloc.MFactoryHelper;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.crashfilter.memory.mloc.StructuredMLoc;
import ghidra.crashfilter.memory.mloc.Symbol_Bottom;
import ghidra.crashfilter.memory.mloc.Symbol_Top;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class EnvManager { // singleton
	Env env = null;
	RTable rTable = null;
	int count;

	private ILatticeGraph<InstructionGraphNode> instGraph;
	private ILatticeGraph<InstructionGraphNode> reilGraph;
	// HeapChecker heapChecker = new HeapChecker(graph);

	private EnvManager(Env env) throws MLocException {
		this.env = env;
		initFirst();
		init();
	}

	public void setEnv(Env env) {
		this.env = env;
	}

	public Env getEnv() {
		return env;
	}

	public void setRTable(RTable rTable) {
		this.rTable = rTable;
	}

	public RTable getRTable() {
		return rTable;
	}

	public Env initFirst() throws MLocException {

		StructuredMLoc sp = null;
		StructuredMLoc esp = null;
		StructuredMLoc heap = null;
		StructuredMLoc ebp = null;
		StructuredMLoc lr = null;
		StructuredMLoc initMLoc_stack = null;
		StructuredMLoc initMLoc_oldebp = null;
		StructuredMLoc retAddr = null;
		Set<IValue> vs;

		/****************** x86 ********************/
		// init esp-> stack0
		esp = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("RSP")).c2(new Val(0)).build();
		initMLoc_stack = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("stack")).c2(new Val(0)).build();

		vs = new HashSet<IValue>();
		vs.add(initMLoc_stack);

		putElements(esp, vs);
		// init ebp-> old ebp
		ebp = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("RBP")).c2(new Val(0)).build();
		initMLoc_oldebp = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("oldebp")).c2(new Val(0))
				.build();
		vs = new HashSet<IValue>();
		vs.add(initMLoc_oldebp);
		putElements(ebp, vs);
		/*******************************************/

		// init heap->
		heap = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("heap")).c2(new Val(0)).build();
		vs = new HashSet<IValue>();
		putElements(heap, vs);

		/******************* Arm *******************/
		// for Arm , SP init
		sp = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("SP")).c2(new Val(0)).build();
		initMLoc_stack = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("stack")).c2(new Val(0)).build();

		vs = new HashSet<IValue>();
		vs.add(initMLoc_stack);

		putElements(sp, vs);

		// for Arm , LR init
		lr = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("LR")).c2(new Val(0)).build();
		retAddr = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("retAddr")).c2(new Val(0)).build();

		vs = new HashSet<IValue>();
		vs.add(initMLoc_stack);

		putElements(sp, vs);
		/**************************************/
		// print();
		return env;

	}

	public Env init() throws MLocException {
		Set<IValue> value = new HashSet<IValue>();

		// for x86
		/********************/
		initRegBottom("RAX");
		initRegBottom("RBX");
		initRegBottom("RCX");
		initRegBottom("RDX");
		initRegBottom("RDI");
		initRegBottom("RSI");
		initRegBottom("R8");
		initRegBottom("R9");
		initRegBottom("R10");
		initRegBottom("R11");
		initRegBottom("R12");
		initRegBottom("R13");
		initRegBottom("R14");
		initRegBottom("R15");
		initRegBottom("ZF");
		initRegBottom("OF");
		initRegBottom("CF");
		initRegBottom("SF");
		/********************/

		// for temp reg
		for (int i = 0; i < 50; i++) {
			initRegBottom("t" + i);
		}

		// for arm
		/********************/
		initRegBottom("LR");
		initRegBottom("C");
		initRegBottom("N");
		initRegBottom("V");
		initRegBottom("PC");

		for (int i = 0; i < 8; i++) {
			initRegBottom("R" + i);
			initArmRegister("R" + i);
		}
		/********************/
		return env;
	}

	private void initRegBottom(String str) throws MLocException {
		Set<IValue> value = new HashSet<IValue>();

		StructuredMLoc init_reg = null;
		Symbol_Bottom init_value = null;

		init_reg = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister(str)).c2(new Val(0))
				.build();
		init_value = Symbol_Bottom.getSymbolBottom();

		value.add(init_value);
		putElements(init_reg, value);
	}

	private void initArmRegister(String str) throws MLocException {
		Set<IValue> value = new HashSet<IValue>();

		StructuredMLoc init_reg = null;
		Symbol_Bottom init_bottom = null;
		StructuredMLoc init_Oldreg = null;

		init_reg = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister(str)).c2(new Val(0))
				.build();

		init_Oldreg = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister("OLD_" + str))
				.c2(new Val(0)).build();

		init_bottom = Symbol_Bottom.getSymbolBottom();

		value.add(init_bottom);
		value.add(init_Oldreg);
		putElements(init_reg, value);
	}

	static EnvManager EnvMGR = null;

	public static EnvManager getEnvManager() throws MLocException {

		if (EnvMGR != null)
			return EnvMGR;
		else
			return new EnvManager(new Env());
	}

	public void oneReilInst(Env env, PcodeOp inst) throws MLocException {
		setEnv(env);
		oneReilInst(inst);
	}

	void oneReilInst(PcodeOp inst) throws MLocException {

		Varnode input0 = inst.getInput(0);
		Varnode input1 = inst.getInput(1);

		Varnode output = inst.getOutput();

		switch (inst.getOpcode()) {
		case PcodeOp.INT_ADD: // addition
			addOperation(input0, input1, output);
			break;
		case PcodeOp.INT_AND: // binary and
			andOperation(input0, input1, output);
			break;
		case PcodeOp.INT_LEFT:
			bshOperation(input0, input1, output, "INT_LERT");
		case PcodeOp.INT_RIGHT: // binary shift
			bshOperation(input0, input1, output, "INT_RIGHT");
			break;
		case PcodeOp.INT_DIV: // unsigned division
			divOperation(input0, input1, output);
			break;
		case PcodeOp.LOAD:

			ldmOperation(input0, input1, output);
			break;
		case PcodeOp.INT_MULT: // unsigned multiplication
			mulOperation(input0, input1, output);
			// operationINT_MUL(input0, input1, output);
			break;
		case PcodeOp.INT_OR: // bitwise Or
			orOperation(input0, input1, output);
			break;
		case PcodeOp.STORE: // store to memory
			stmOperation(input0, input1, output);
			break;
		case PcodeOp.COPY: // store to register
			strOperation(input0, output);
			// strOperation(input0, output);
			break;
		case PcodeOp.INT_SUB: // subtract
			subOperation(input0, input1, output);
			break;
		case PcodeOp.INT_XOR:
			xorOperation(input0, input1, output);
			break;
		default: // FLOAT instruction no handling
			break;
		}

	}

	private void bshOperation(Varnode op1, Varnode op2, Varnode op3, String op) throws MLocException {
		bitOperation(op1, op2, op3, op);
	}

	private StructuredMLoc op2StructedMLoc(Varnode op3) throws MLocException {
		StructuredMLoc result = null;

		result = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister(op3)).c2(new Val(0))
				.build();
		return result;
	}

	private void strOperation(Varnode op1, Varnode op3) throws MLocException {
		Set<IValue> op1locs = opinit(op1);
		StructuredMLoc op3reg = op2StructedMLoc(op3);
		Set<IValue> value = copyIValueSet(op1locs);
		putElements(op3reg, value);
	}

	private void stmOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		if (op1.isRegister()) {
			StructuredMLoc structOp1 = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister(op1))
					.c2(new Val(0)).build();
			Set<IValue> op1locs = env.get(structOp1);
			op1locs = copyIValueSet(op1locs);

			StructuredMLoc op3reg = op2StructedMLoc(op3);
			Set<IValue> op3mem = env.get(op3reg);
			if (op3mem == null) {
				return;
			}

			for (IValue v : op3mem) {
				if (v instanceof IALoc) {
					putElements((IALoc) v, op1locs);
				} else {
					// can not store (ex. key is constant)
				}
			}
		} else if (op1.isConstant()) {
			Set<IValue> op1locs = new HashSet<>();
			long value = op1.getOffset();
			op1locs.add(new Val(value));
			StructuredMLoc op3reg = op2StructedMLoc(op3);

			Set<IValue> op3mem = env.get(op3reg);
			op3mem = copyIValueSet(op3mem);

			if (op3mem == null) {
				return;
			}

			for (IValue v : op3mem) {
				if (v instanceof IALoc) {
					putElements((IALoc) v, op1locs);
				} else {
					// can not store (ex. key is constant)
				}
			}

		}

	}

	private void ldmOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		Set<IValue> op1locs = opinit(op1);
		StructuredMLoc op3loc = StructuredMLoc.newStructuredMLoc(op3);

		for (IValue op1v : op1locs) {
			Set<IValue> result = env.get(op1v);
			if (result == null) {
				result = new HashSet<IValue>();
				result.add(Symbol_Top.getSymbolTop());
			}
			putElements(op3loc, result);

		}
	}

	private void addOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		subNAddOperation_(op1, op2, op3, 1);
	}

	private void subOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		subNAddOperation_(op1, op2, op3, -1);
	}

	private void subNAddOperation_(Varnode op1, Varnode op2, Varnode op3, int flag) throws MLocException {
		Set<IValue> op1locs = opinit(op1);
		Set<IValue> op2locs = opinit(op2);
		StructuredMLoc op3reg = op2StructedMLoc(op3);
		Set<IValue> result = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if (op1loc instanceof IRegister) {
					if (op2loc instanceof Val) {
						Val v = new Val(((Val) op2loc).getValue() * flag);

						StructuredMLoc val = new StructuredMLoc.StructuredMLocBuilder().reg2((IRegister) op1loc)
								.c2(new Val(v.getValue())).build();
						result.add(val);

					}
				} else if (op1loc instanceof StructuredMLoc) {
					if (op2loc instanceof Val) {

						Val v1 = ((StructuredMLoc) op1loc).getC2();
						Val v2 = (Val) op2loc;

						long i1 = v1.getValue();
						long i2 = v2.getValue();
						i2 = i2 * flag;

						Val v = new Val(i1 + i2);

						StructuredMLoc val = new StructuredMLoc.StructuredMLocBuilder()
								.reg2(((StructuredMLoc) op1loc).getReg2()).c2(new Val(v.getValue())).build();
						result.add(val);
					}
				} else if (op1loc instanceof Val) {
					if (op2loc instanceof IRegister) {
						if (flag > 0)// add
						{
							Val v = new Val(((Val) op1loc).getValue() * flag);

							StructuredMLoc val = new StructuredMLoc.StructuredMLocBuilder().reg2((IRegister) op2loc)
									.c2(new Val(v.getValue())).build();
							result.add(val);
						} else // val-register => Top
						{
							result.add(Symbol_Top.getSymbolTop());
						}
					} else if (op2loc instanceof StructuredMLoc) {
						if (flag > 0) {
							Val v1 = (Val) op1loc;
							StructuredMLoc v2 = (StructuredMLoc) op2loc;

							Val v = Val.add(v1, v2.getC2());
							v2.setC2(v);
							result.add(v2.copy());
						} else {
							result.add(Symbol_Top.getSymbolTop());
						}
					} else if (op2loc instanceof Val) {
						long i1 = ((Val) op1loc).getValue();
						long i2 = ((Val) op2loc).getValue();
						i2 = i2 * flag;
						Val val = new Val(i1 + i2);
						result.add(val);
					} else if (op2loc instanceof Symbol_Bottom) {
						result.add(Symbol_Top.getSymbolTop());
					} else if (op2loc instanceof Symbol_Top) {
						result.add(Symbol_Top.getSymbolTop());
					}

				} else if (op1loc instanceof Symbol_Bottom) {
					result.add(Symbol_Top.getSymbolTop());
				} else if (op1loc instanceof Symbol_Top) {
					result.add(Symbol_Top.getSymbolTop());
				}

			}
		}
		putElements(op3reg, result);
	}

	private void andOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {

//		if(op2.getValue().equals("4294967295") )
//		{			
//			strOperation(op1,null,op3);
//			return;
//		}
//		else if(op1.getValue().equals("4294967295"))
//		{
//			strOperation(op2,null,op3);
//			return;
//		}
//		
//		if( (op2.getValue().equals("4294967280") && op1.getValue().equals("esp") )	) 
//		{			
//			strOperation(op1,null,op3);
//			return;
//		}
//		else if( op1.getValue().equals("4294967280") && op2.getValue().equals("esp") )
//		{
//			strOperation(op2,null,op3);
//			return;
//		}

		bitOperation(op1, op2, op3, "and");

	}

	private void bitOperation(Varnode op1, Varnode op2, Varnode op3, String opName) throws MLocException {
		Set<IValue> op1locs = opinit(op1);
		Set<IValue> op2locs = opinit(op2);
		StructuredMLoc op3reg = op2StructedMLoc(op3);
		Set<IValue> result = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if (op1loc instanceof Val && op2loc instanceof Val) {
					long i1 = ((Val) op1loc).getValue();
					long i2 = ((Val) op2loc).getValue();
					if (opName.equals("and")) {
						Val val = new Val(i1 & i2);
						result.add(val);
					} else if (opName.equals("or")) {
						Val val = new Val(i1 | i2);
						result.add(val);
					} else if (opName.equals("xor")) {
						Val val = new Val(i1 ^ i2);
						result.add(val);
					} else if (opName.equals("INT_LEFT")) {
						Val val = new Val(i1 << i2);
						result.add(val);
					} else if (opName.equals("INT_RIGHT")) {
						Val val = new Val(i1 >> i2);
						result.add(val);
					}
				} else {
					result.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, result);
	}

	private void orOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		bitOperation(op1, op2, op3, "or");
	}

	private void xorOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		bitOperation(op1, op2, op3, "xor");
	}

	private void mulNDivOperation(Varnode op1, Varnode op2, Varnode op3, String opName) throws MLocException {
		Set<IValue> op1locs = opinit(op1);
		Set<IValue> op2locs = opinit(op2);
		StructuredMLoc op3reg = op2StructedMLoc(op3);
		Set<IValue> result = new HashSet<IValue>();

		for (IValue op1loc : op1locs) {
			for (IValue op2loc : op2locs) {
				if (op1loc instanceof Val && op2loc instanceof Val) {
					long i1 = ((Val) op1loc).getValue();
					long i2 = ((Val) op2loc).getValue();
					long intValue = 0;
					if (opName.equals("mul")) {
						intValue = i1 * i2;
					} else if (opName.equals("div")) {
						intValue = i1 / i2;
					} else if (opName.equals("mod")) {
						intValue = i1 % i2;
					}
					Val val = new Val(intValue);
					result.add(val);

				} else if (op1loc instanceof Symbol_Bottom) {
					result.add(Symbol_Top.getSymbolTop());
				} else if (op1loc instanceof Symbol_Top) {
					result.add(Symbol_Top.getSymbolTop());
				}

			}
		}
		putElements(op3reg, result);
	}

	private void mulOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		mulNDivOperation(op1, op2, op3, "mul");
	}

	private void divOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		mulNDivOperation(op1, op2, op3, "div");
	}

	private void modOperation(Varnode op1, Varnode op2, Varnode op3) throws MLocException {
		mulNDivOperation(op1, op2, op3, "mod");
	}

	private Set<IValue> opinit(Varnode op) throws MLocException {

		Set<IValue> result = null;
		if (op.isUnique()) {
//			LogConsole.log("opinit :  -tx \n" );
			result = new HashSet<IValue>();
			result.add(Symbol_Top.getSymbolTop());
			return result;
		}

		if (op.isRegister()) {
			StructuredMLoc struct = new StructuredMLoc.StructuredMLocBuilder().reg2(MFactoryHelper.newIRegister(op))
					.c2(new Val(0)).build();
			result = copyIValueSet(env.get(struct));
		} else if (op.isConstant()) {
			result = new HashSet<IValue>();
			long val = op.getOffset();
			result.add(new Val(val));
		}

		return result;
	}

	public void runValueAnalysis() {
//		LogConsole.log("---------Start-----------\n");
		for (InstructionGraphNode inst : instGraph.getNodes()) {

			if (inst.isEnd()) {
				deleteTempRegster();
			}
			// LogConsole.log(inst.getInstruction().toString()+"\n");

			/*
			 * //heap checker long instLong = inst.getInstruction().getAddress().toLong();
			 * 
			 * if(heapChecker.eaxHeapMemoryCheck(instLong)) { try { env = initEax2Heap(); }
			 * catch (MLocException e) { e.printStackTrace(); } }
			 */
			try {
				oneReilInst(inst.getPcode());
			} catch (MLocException e) {
				e.printStackTrace();
			}
			// print();

//			LogConsole.log("--------------------\n");
		}

		deleteTempRegster();
//		LogConsole.log("-----------end---------\n");
	}

	private void deleteTempRegster() {

//		LogConsole.log("-------delete temp start--------\n");
		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IALoc> keyset = env.keySet();
		for (IALoc key : keyset) {
			if (key instanceof StructuredMLoc) {
//				LogConsole.log(key+"\n");
				if (((StructuredMLoc) key).getReg2() instanceof TempReg) {
//					LogConsole.log("tempreg : "+((StructuredMLoc)key).getReg2()+"\n");
					toBeRemoved.add(key);
				}
			}

		}
		for (IALoc key : toBeRemoved) {
			env.remove(key);
		}

//		LogConsole.log("-------delete temp end--------\n");
	}

	private void print() {
		for (IALoc ialoc : env.keySet()) {
//			LogConsole.log("Key : "+ialoc+"\n");
//			LogConsole.log("\tValue : "+env.get(ialoc)+"\n" );
		}
	}

	private void putElements(IALoc key, Set<IValue> value) {
		if (key instanceof Val) {
			return;
		}
		if (env.containsKey(key)) {
			env.remove(key);
		}
		env.put(key, value);
	}

	private Set<IValue> copyIValueSet(Set<IValue> vT) {
		if (vT == null) {
			return null;
		}
		Set<IValue> saveVT = new HashSet<IValue>();
		for (IValue value : vT) {
			IValue copyValue = null;
			if (value instanceof Val) {
				Val val = new Val(((Val) value).getValue());
				copyValue = val;

			} else if (value instanceof StructuredMLoc) {
				StructuredMLoc val = ((StructuredMLoc) value).copy();
				copyValue = val;
			} else {
				copyValue = value; // top or bottom..
			}

			saveVT.add(copyValue);
		}
		return saveVT;
	}

	public Env initEax2Heap() throws MLocException {
		// TODO
		StructuredMLoc structEax = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("eax")).c2(new Val(0))
				.build();
		StructuredMLoc structHeap = new StructuredMLoc.StructuredMLocBuilder().reg2(new ActualReg("heap"))
				.c2(new Val(0)).build();

		Set<IValue> vs = new HashSet<IValue>();
		vs.add(structHeap);

		putElements(structEax, vs);

		return getEnv();

	}
}
