package ghidra.crashfilter.memory;

import java.util.List;

import ghidra.crashfilter.BinNavi.mono.DefaultStateVector;
import ghidra.crashfilter.BinNavi.mono.DownWalker;
import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.ITransformationProvider;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.MonotoneSolver;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.helper.CallStackCleaner;
import ghidra.crashfilter.helper.HeapChecker;
import ghidra.crashfilter.memory.RTable.IRSetManager;
import ghidra.crashfilter.memory.RTable.RTable;
import ghidra.crashfilter.memory.env.Env;
import ghidra.crashfilter.memory.env.EnvManager;
import ghidra.crashfilter.memory.mloc.MFactoryHelper;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class MLocAnalysis {
	private ILatticeGraph<InstructionGraphNode> graph;
	private Function function;
	private HeapChecker heapChecker;
	private int count = 0;
	private Program prog;

	public MLocAnalysis(ILatticeGraph<InstructionGraphNode> graph, Function function) {
		this.graph = graph;
		this.function = function;
		this.prog = function.getProgram();
		heapChecker = HeapChecker.initHeapChecker(graph, function);
		MFactoryHelper.setLangeuage(prog.getLanguage());
	}

	public IStateVector<InstructionGraphNode, MLocLatticeElement> mLocAnalysis() throws MLocException {

		MLocLattice lattice;
		IStateVector<InstructionGraphNode, MLocLatticeElement> startVector;
		IStateVector<InstructionGraphNode, MLocLatticeElement> endVector;

		ITransformationProvider<InstructionGraphNode, MLocLatticeElement> transferFunction;
		DownWalker walker;
		MonotoneSolver<InstructionGraphNode, MLocLatticeElement, Object, MLocLattice> solver;

		lattice = new MLocLattice();

		startVector = initializeState(graph);
		transferFunction = new MLocTransferFunction();
		walker = new DownWalker();
		// LogConsole.log("why?");

		solver = new MonotoneSolver<InstructionGraphNode, MLocLatticeElement, Object, MLocLattice>(graph, lattice,
				startVector, transferFunction, walker, null);
		endVector = solver.solve();
		// LogConsole.log("end?");
		return endVector;
	}

	private IStateVector<InstructionGraphNode, MLocLatticeElement> initializeState(
			ILatticeGraph<InstructionGraphNode> inputGraph) throws MLocException {

		IStateVector<InstructionGraphNode, MLocLatticeElement> startVector = new DefaultStateVector<InstructionGraphNode, MLocLatticeElement>();

		heapChecker.findHeapAllocation(function);

		List<InstructionGraphNode> instList = inputGraph.getNodes();
		MLocLatticeElement state;

		for (InstructionGraphNode inst : graph.getNodes()) {

			state = new MLocLatticeElement();

			RTable initializedRTable = initRTable();
			Env initializedEnv = initEnv();

			state.setInst(inst);
			state.setRTable(initializedRTable);
			state.setEnv(initializedEnv);

			startVector.setState(inst, state);
		}
		return startVector;
	}

	private RTable initRTable() throws MLocException {
		RTable rTable = new RTable();
		ActualReg.initActualReg(prog.getLanguage());
		IRSetManager irsm = IRSetManager.getIRSetManager(this.function.getProgram());
		irsm.setRTable(rTable);

		rTable = irsm.initFirst();
		// rTable = irsm.init();
		return rTable;
	}

	private Env initEnv() throws MLocException {
		Env env = new Env();
		EnvManager eManager = EnvManager.getEnvManager();
		eManager.setEnv(env);

		// env = eManager.initFirst();
		env = eManager.init();
		return env;
	}

	public class MLocTransferFunction implements ITransformationProvider<InstructionGraphNode, MLocLatticeElement> {

		public MLocLatticeElement transform(InstructionGraphNode node, MLocLatticeElement currentState,
				MLocLatticeElement inputState) {
			MLocLatticeElement transformedState = new MLocLatticeElement();
			Env inputEnv = inputState.getEnv();
			Env currentEnv = currentState.getEnv();
			Env transformed_Env;

			if (inputEnv == null) {
				transformed_Env = currentEnv;
			} else {
				if (inputEnv.size() == 0) {
					transformed_Env = currentEnv;
				} else {
					transformed_Env = inputEnv;
				}
			}

			RTable inputRTable = inputState.getRTable();
			RTable currentRTable = currentState.getRTable();

			RTable transformed_RTable;
			if (inputRTable == null) {
				transformed_RTable = currentRTable;
			} else {
				if (inputRTable.size() == 0) {
					transformed_RTable = currentRTable;
				} else {
					transformed_RTable = inputRTable;
				}

			}

			IRSetManager rTableManager = IRSetManager.getIRSetManager(prog);
			rTableManager.setEnv(transformed_Env);
			rTableManager.setRTable(transformed_RTable);

			// trnasfer
			CallStackCleaner callStackCleaner = CallStackCleaner.getCallStackCleaner();
			if (callStackCleaner.isToBeClearedStack(node)) {
				// System.out.println("call stack cleaning...");
				callStackCleaner.clearCallStack_Ebp(transformed_RTable, transformed_Env);
			}

			try {
				rTableManager.oneReilInst(node.getPcode());
			} catch (MLocException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// state setting
			inputRTable = transformed_RTable;
			currentRTable = transformed_RTable;
			currentState.setRTable(transformed_RTable);

			inputEnv = transformed_Env;
			currentEnv = transformed_Env;
			currentState.setEnv(transformed_Env);

			transformedState.setInst(node);
			transformedState.setEnv(transformed_Env);
			transformedState.setRTable(transformed_RTable);

			return transformedState;
		}
	}

	public void deleteTempReg(IStateVector<InstructionGraphNode, MLocLatticeElement> endVector) {
		MLocLatticeElement state = null;
		for (InstructionGraphNode inst : graph.getNodes()) {
			state = endVector.getState(inst);
			state.getRTable().deleteTempReg();
			state.getEnv().deleteTempReg();
		}
	}

	public void deleteBottomSymbol(IStateVector<InstructionGraphNode, MLocLatticeElement> vector) {
		MLocLatticeElement state = null;
		for (InstructionGraphNode inst : graph.getNodes()) {
			state = vector.getState(inst);
			state.getEnv().deleteNullNBottom();
			state.getRTable().deleteNullNBottom();
		}
	}
	// private

}
