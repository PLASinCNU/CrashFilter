/* ###
 * IP: GHIDRA
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
package ghidra.crashfilter;

import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.InstructionGraph;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.dataflow.DefLatticeElement;
import ghidra.crashfilter.dataflow.DefUseChain;
import ghidra.crashfilter.dataflow.ReachingDefinition;
import ghidra.crashfilter.helper.CallStackCleaner;
import ghidra.crashfilter.helper.CrashSourceAdder;
import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.helper.GlobalVariableAnalysis;
import ghidra.crashfilter.helper.HeapChecker;
import ghidra.crashfilter.helper.InterProcedureMode;
import ghidra.crashfilter.helper.ReturnValueAnalysis;
import ghidra.crashfilter.helper.VariableFinder;
import ghidra.crashfilter.memory.MLocAnalysis;
import ghidra.crashfilter.memory.MLocLatticeElement;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class CrashFilterAnalyzer {

	private Program prog;
	private PseudoDisassembler pdis;

	private boolean memoryAnalysisCheck = true;
	private boolean crashSrcAnalysisCheck = true;
	private boolean interProcedureAnalysisCheck = true;
	private boolean callCountCheck = false;
	private boolean availableDefinitionCheck = false;
	
	private ConsoleService console;

	public void setConsole(ConsoleService console) {
		this.console = console;
		GhidraConsolePrint.setConsoleService(console);
	}

	private int e_path_cnt = 0;
	private int pe_path_cnt = 0;
	private int e_cnt = 0;
	private int pe_cnt = 0;
	private int ne_cnt = 0;
	private int ne_call_cnt = 0;
	private int totalTime = 0;
	private int escapableAnalysisCount = 0;
	private int e_call_cnt = 0;

	private Map<Address, Dangerousness> functionDangerousnessDynamicTable = new HashMap<Address, Dangerousness>();

	public CrashFilterAnalyzer(Program prog) {
		// TODO: Name the analyzer and give it a description.
		this.prog = prog;
		pdis = new PseudoDisassembler(prog);
	}

	public Dangerousness crashAnalyze(String crashAddr) {
		Dangerousness rate = runSingleCrash(InterProcedureMode.NORMAL, crashAddr);
		// Println("this crash's rate is ", rate.toString());
		return rate;
	}

	private Dangerousness runSingleCrash(InterProcedureMode interProcedureAnalysisMode, String crashaddr) {
		Dangerousness dagnerousness = Dangerousness.NE;
		ILatticeGraph<InstructionGraphNode> graph = null;
		IStateVector<InstructionGraphNode, DefLatticeElement> dfResult = null;
		IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;
		// Long crashAddr;
		// LogConsole.log("Parsing File Number : " + crashPointToFuncAddr.size() +
		// "\n\n");

		int viewIndex = 0;

		// crashAddr = Long.toHexString(crashAddress);

//		LogConsole.log("now analyzing : " + Long.toHexString(crashPointAddress) + "\n");
//		System.out.println("\n now analyzing : " + Long.toHexString(crashPointAddress));
		long before = System.currentTimeMillis();

		Function curReilFunc = null;
		List<PcodeOp> crashReilInst = new ArrayList<PcodeOp>();
		List<InstructionGraphNode> taintSourceInstructionGraphNodes;

		AddressFactory addressFactory = prog.getAddressFactory();
		Address crashPointAddress = addressFactory.getAddress(crashaddr);
		Function curFunc = prog.getFunctionManager().getFunctionContaining(crashPointAddress);
		

		graph = InstructionGraph.create(curFunc);
		taintSourceInstructionGraphNodes = ((InstructionGraph)graph).getNodes(crashPointAddress);
		GhidraConsolePrint.println("Crash Instructions ");
		for(InstructionGraphNode ign : taintSourceInstructionGraphNodes) {
			GhidraConsolePrint.println(ign.toString());
		}
		/************* Analysis Option Check ********************/
		if (memoryAnalysisCheck) {
			try {
				mLocResult = memoryAnalysis(graph, curFunc);
			} catch (MLocException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}


		// VariableFinder 인터프로시쥬럴을 할 때만 필요.
		// normal 할 때는 가비지
		VariableFinder vf = new VariableFinder(prog, curFunc);
//		if (availableDefinitionCheck) {
//			List<Long> virtualCrashAddrs = new ArrayList<>();
//			virtualCrashAddrs.add(crashPointAddress);
//			AvailableDefinition ada = new AvailableDefinition(graph, virtualCrashAddrs, vf);
//			dfResult = ada.runADAnalysis(interProcedureAnalysisMode);
//			LogConsole.log("== end ad analysis ==\n");
//		} else {
		List<Address> crashAddrs = new ArrayList<>();
		crashAddrs.add(crashPointAddress);
		ReachingDefinition rda = new ReachingDefinition(graph, crashAddrs, vf);
		dfResult = rda.runRDAnalysis(interProcedureAnalysisMode);
		// LogConsole.log("== end rd analysis ==\n");
		// }

		// rda.printAD(dfResult);
		// rda.printRD(dfResult);
		GhidraConsolePrint.println("==start du analysis 1==");
		DefUseChain du = new DefUseChain(dfResult, graph, crashPointAddress, crashSrcAnalysisCheck);
		du.setMemoryResult(mLocResult);
		try {
			du.defUseChaining(taintSourceInstructionGraphNodes);
		} catch (MLocException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		 GhidraConsolePrint.println("== end DU analysis ==");
		// du.printChain();
		
		crashSrcAnalysis(interProcedureAnalysisMode, crashPointAddress, graph, taintSourceInstructionGraphNodes, vf,
				du);
		
		ExploitableAnalysis exploitableAnalysis = new ExploitableAnalysis(du.getDuGraphs(), curFunc, crashPointAddress);

		switch (interProcedureAnalysisMode) {
		case NORMAL:

			if (exploitableAnalysis.isTaintSink()) {
				// makeView(crashPointToFuncAddr, viewIndex, crashPointAddress, curFunc,
				// exploitableAnalysis);
				dagnerousness = exploitableAnalysis.getDangerousness();
				e_call_cnt++;
			}

			if (needToInterProcedureAnalysis(dagnerousness)) {
				Dangerousness dagnerousness_inter = Dangerousness.E;
				try {
					dagnerousness_inter = interProcedureAnalysis(graph, curFunc, exploitableAnalysis);
				} catch (MLocException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				dagnerousness = getMoreDangerousOne(dagnerousness, dagnerousness_inter);
				ne_call_cnt++;
			} else {
				if (needToCountFunctionCall(dagnerousness)) {

					if (hasFunctionCalls(curFunc)) {
						dagnerousness = Dangerousness.PE;
						ne_call_cnt++;
					}
				}
			}
			
			break;

		case FUNCTIONAnalysis:
			Set<Function> calleeFunction = curFunc.getCalledFunctions(null);
			Dangerousness dagnerousness_global = Dangerousness.NE;
			dagnerousness_global = glovalVariableAnalysis(curFunc, calleeFunction);

			ReturnValueAnalysis returnValueAnalysis = new ReturnValueAnalysis(du.getDuGraphs(), curFunc, dfResult,
					graph);

			if (returnValueAnalysis.isTaintSink() || exploitableAnalysis.isTaintSink()) {
				dagnerousness = getMoreDangerousOne(returnValueAnalysis.getDnagerousness(),
						exploitableAnalysis.getDangerousness());

				// makeView(crashPointToFuncAddr, viewIndex, crashPointAddress, curFunc,
				// returnValueAnalysis);
			}
			dagnerousness = getMoreDangerousOne(dagnerousness, dagnerousness_global);
			break;

		default:
			break;
		}

		// add escape analysis -->
		// src : returned value
		// sink : return value

		dagnerousness = escapableAnalysis(dagnerousness, graph, dfResult, curFunc, du);

		e_path_cnt += exploitableAnalysis.getTotal_e_count();
		pe_path_cnt += exploitableAnalysis.getTotal_pe_count();

		GhidraConsolePrint.println("==========end Exploitable analysis ===========");

		long after = System.currentTimeMillis();
		long processingTime = after - before;

		// LogConsole.log(curFunc.getName() + "-- time : " + processingTime + "\n\n");
		totalTime += processingTime;
		viewIndex++;

		functionDangerousnessDynamicTable.put(crashPointAddress, dagnerousness);
		return dagnerousness;
	}

	private IStateVector<InstructionGraphNode, MLocLatticeElement> memoryAnalysis(
			ILatticeGraph<InstructionGraphNode> graph, Function curFunc) throws MLocException {
		// TODO Auto-generated method stub
//		LogConsole.log("== start locAnalysis analysis ==\n");
//
//		LogConsole.log("== find Heap Location ==\n");
		HeapChecker.initHeapChecker(graph, curFunc);

		CallStackCleaner callStackCleaner = CallStackCleaner.getCallStackCleaner();
		callStackCleaner.initCallStackCleaner(curFunc, graph);

		MLocAnalysis mLocAnalysis = new MLocAnalysis(graph, curFunc);

		// LogConsole.log("== analysis start ==\n");
		IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = mLocAnalysis.mLocAnalysis();
		mLocAnalysis.deleteTempReg(mLocResult);
		mLocAnalysis.deleteBottomSymbol(mLocResult);
		// LogConsole.log("== end memoryAnalysis ==\n");
		// envAnalysis.printEnv(envResult);
		// LogConsole.log("== end print env analysis ===\n");

		return mLocResult;

	}

	private Dangerousness getMoreDangerousOne(Dangerousness dagnerousness_1, Dangerousness dagnerousness_2) {
		return dagnerousness_1.getDangerous() > dagnerousness_2.getDangerous() ? dagnerousness_1 : dagnerousness_2;
	}

	private void crashSrcAnalysis(InterProcedureMode interProcedureAnalysisMode, Address crashPointAddress,
			ILatticeGraph<InstructionGraphNode> graph, List<InstructionGraphNode> taintSourceInstructionGraphNodes,
			VariableFinder vf, DefUseChain du) {
		// crashSrcAnalysis
		if (crashSrcAnalysisCheck) {
			if (interProcedureAnalysisMode != InterProcedureMode.NORMAL) {
				taintSourceInstructionGraphNodes.clear();
			}
			taintSourceInstructionGraphNodes
					.addAll(CrashSourceAdder.getInstructions(graph, crashPointAddress, interProcedureAnalysisMode, vf));
		}
		for (InstructionGraphNode taintSourceInstructionGraphNode : taintSourceInstructionGraphNodes) {
			du.createDefUseGraph(taintSourceInstructionGraphNode);
		}
	}

	private boolean needToInterProcedureAnalysis(Dangerousness dagnerousness) {

		if (interProcedureAnalysisCheck) {
			return (dagnerousness == Dangerousness.NE) || (dagnerousness == Dangerousness.PE);
		}

		return false;
	}

	private Dangerousness glovalVariableAnalysis(Function curFunc, Set<Function> calleeFunctions) {
		// remove useless argument
		GlobalVariableAnalysis globalVariableAnalysis = new GlobalVariableAnalysis(prog, curFunc);
		if (globalVariableAnalysis.dontUseGlobalVariable()) {
			return Dangerousness.NE;
		}
		for (Function calleeFunction : calleeFunctions) {

			// Function curFunc = ModuleHelpers.getFunction(module,
			// crashPointToFuncAddr.get(crashPointAddress).getFuncAddr());
			GlobalVariableAnalysis globalVariableAnalysis_callee = new GlobalVariableAnalysis(prog, calleeFunction);
			if (globalVariableAnalysis.hasSameGlobalVaraible(globalVariableAnalysis_callee)) {
				return Dangerousness.PE;
			}
		}
		return Dangerousness.NE;
	}

	private boolean needToCountFunctionCall(Dangerousness dagnerousness) {
		if (callCountCheck) {
			return (dagnerousness == Dangerousness.PE || dagnerousness == Dangerousness.NE)
					&& !interProcedureAnalysisCheck;
		}
		return false;
	}

	private boolean hasFunctionCalls(Function curFunc) {
		Set<Function> callees = curFunc.getCalledFunctions(null);
		return callees.size() > 0;
	}

	private Dangerousness interProcedureAnalysis(ILatticeGraph<InstructionGraphNode> graph, Function curFunc,
			ExploitableAnalysis exploitableAnalysis) throws MLocException {

		Dangerousness dagnerousness = exploitableAnalysis.getDangerousness();

		if (dontHaveToInterProcedureAnalysis(curFunc)) {
			return dagnerousness;
		}

		Set<Function> calleeFunction = curFunc.getCalledFunctions(null);
		// Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();

		Dangerousness dangerousness_g = Dangerousness.NE;
		dangerousness_g = glovalVariableAnalysis(curFunc, calleeFunction);

		Dangerousness dangerousness_f = Dangerousness.NE;

		for (Function callee : calleeFunction) {
			Dangerousness dangerousness_f_temp = getCalleesDangerousness(callee);

			functionDangerousnessDynamicTable.put(callee.getEntryPoint(), dangerousness_f);
			dangerousness_f = getMoreDangerousOne(dangerousness_f_temp, dangerousness_f);
		}

		dagnerousness = getMoreDangerousOne(dangerousness_f, dangerousness_g);
		return dagnerousness;
	}

	private Dangerousness getCalleesDangerousness(Function callee) throws MLocException {

		Dangerousness dangerousness_f;
		dangerousness_f = runSingleCrash(InterProcedureMode.FUNCTIONAnalysis, callee.getEntryPoint().toString());

		return dangerousness_f;
	}

	private boolean dontHaveToInterProcedureAnalysis(Function curFunc) {
		return !hasFunctionCalls(curFunc);
	}

	private Dangerousness escapableAnalysis(Dangerousness dagnerousness, ILatticeGraph<InstructionGraphNode> graph,
			IStateVector<InstructionGraphNode, DefLatticeElement> RDResult, Function curFunc, DefUseChain du) {
		ReturnValueAnalysis escapableAnalysis = new ReturnValueAnalysis(du.getDuGraphs(), curFunc, RDResult, graph);
		if (escapableAnalysis.isTaintSink()) {
			dagnerousness = getMoreDangerousOne(dagnerousness, Dangerousness.PE);
			if (dagnerousness.getDangerous() > Dangerousness.E.getDangerous()) {
				escapableAnalysisCount++;
			}
		}
		return dagnerousness;
	}
	
	private List<InstructionGraphNode> createTaintedInstructionGraphNodes(Address crashAddr, ILatticeGraph<InstructionGraphNode> iGraph){
		List<InstructionGraphNode> taintedInstructions = new ArrayList<InstructionGraphNode>();
		taintedInstructions = ((InstructionGraph)iGraph).getNodes(crashAddr);
		for(InstructionGraphNode ign : taintedInstructions) {
			switch(ign.getPcode().getOpcode()) {
			case PcodeOp.CALL:
			case PcodeOp.CALLIND:
			case PcodeOp.CALLOTHER:
				// call instruction 일 경우 이 call 함수의 function의 파라미터에 대해서 마킹하는 것이 필요
				for(int i = 1; i < ign.getPcode().getNumInputs(); i++) {
					Varnode input = ign.getPcode().getInput(i);
					input.getDef();
				}
				break;
			default:
				break;
			}
		}
		return taintedInstructions;
	}
}
