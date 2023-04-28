package ghidra.crashfilter.helper;

import java.util.*;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.crashfilter.Dangerousness;
import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.dataflow.DefLatticeElement;
import ghidra.crashfilter.dataflow.DefUseChain;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class ReturnValueAnalysis {
	private IStateVector<InstructionGraphNode, DefLatticeElement> RDResult;
	private List<DefUseChain.DefUseGraph> duGraphs;
	private Function func;
	private Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> taintedReilPaths = new HashMap<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>>();
	private Map<PseudoInstruction, List<PseudoInstruction>> taintedArmPaths = new HashMap<PseudoInstruction, List<PseudoInstruction>>();

	private Dangerousness dnagerousness = Dangerousness.NE;

	public Dangerousness getDnagerousness() {
		return dnagerousness;
	}

	private ILatticeGraph<InstructionGraphNode> graph;

	public ReturnValueAnalysis(List<DefUseChain.DefUseGraph> duGraphs, Function func,
			IStateVector<InstructionGraphNode, DefLatticeElement> RDResult, ILatticeGraph<InstructionGraphNode> graph) {
		this.duGraphs = duGraphs;
		this.func = func;
		this.RDResult = RDResult;
		this.graph = graph;
	}

	public Map<PseudoInstruction, List<PseudoInstruction>> getExploitArmPaths() {
		return taintedArmPaths;
	}

	public Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> getExploitReilPaths() {
		return taintedReilPaths;
	}

	private PseudoInstruction toArmInstruction(DefUseChain.DefUseNode duNode) {
		Program prog = func.getProgram();
		PseudoDisassembler pdis = new PseudoDisassembler(prog);
		PseudoInstruction psi = null;
		;
		try {
			psi = pdis.disassemble(duNode.getInst().getAddr());
		} catch (InsufficientBytesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnknownInstructionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnknownContextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return psi;
	}

	public boolean isTaintSink() {
		boolean isTaintSink = false;

		isTaintSink = isRetrunValueTainted();

		return isTaintSink;
	}

	private boolean isReachableAtReturn(InstructionGraphNode inst) {
		if (RDResult == null) {
			System.out.println("error : RVA- isLastDefOfReturnValue()");
		}

		InstructionGraphNode lastInstruction = getLastInstruction(func);

		DefLatticeElement defLatticeElement = RDResult.getState(lastInstruction);
		if (defLatticeElement == null) {
			System.out.println("DefLatticeElement is null");
			System.exit(-1);
		}

		return isReachableToLastInstruction(inst, defLatticeElement);
	}

	private boolean isReachableToLastInstruction(InstructionGraphNode inst, DefLatticeElement defLatticeElement) {
		return defLatticeElement.getInstList().contains(inst);
	}

	private InstructionGraphNode getLastInstruction(Function func1) {

		InstructionGraphNode lastInst = null;
		
		Address last = func1.getBody().getMaxAddress();
		GhidraConsolePrint.println("Max Address : "+last.toString());
		GhidraConsolePrint.println(Long.toHexString(last.getOffset()));
		for (InstructionGraphNode inst : graph.getNodes()) {
			if(lastInst ==null) lastInst = inst;
			if(inst.getAddr().getOffset() > lastInst.getAddr().getOffset()) lastInst= inst;
		}
		return lastInst;
	}

	private boolean isRetrunValueTainted() {

		searchTaintedRetrunValue();
		if (taintedReilPaths.isEmpty()) {
			return false;
		}

		return true;
	}

	private boolean checkTaintedValue(DefUseChain.DefUseNode node) {

		PcodeOp inst = node.getInst().getPcode();
		InstructionGraphNode lastInstruction = getLastInstruction(func);

		if (inst.equals(lastInstruction.getPcode())) {
			dnagerousness = Dangerousness.PE;
			return true;
		}
		return false;

	}

	private void searchTaintedRetrunValue() {
		// All the graphs is analyzed at this function

		for (DefUseChain.DefUseGraph duGraph : duGraphs) {
			Stack<DefUseChain.DefUseNode> stackDFS = new Stack<DefUseChain.DefUseNode>();
			Set<DefUseChain.DefUseNode> visitedNodes = new HashSet<DefUseChain.DefUseNode>();
			searchTaintRetrunValueDFS(stackDFS, visitedNodes, duGraph.getNodes().get(0));
		}
	}

	private void searchTaintRetrunValueDFS(Stack<DefUseChain.DefUseNode> stackDFS,
			Set<DefUseChain.DefUseNode> visitedNode, DefUseChain.DefUseNode duNode) {

		// current node processing
		visitedNode.add(duNode);
		stackDFS.push(duNode);
		if (checkTaintedValue(duNode)) {
			List<DefUseChain.DefUseNode> exploitPath = new ArrayList<DefUseChain.DefUseNode>();
			exploitPath.addAll(stackDFS);
			taintedReilPaths.put(duNode, exploitPath);

			// printTaintedReilPaths();
		}

		// children iteration
		searchChildren(stackDFS, visitedNode, duNode);
		stackDFS.pop();
	}

	private void searchChildren(Stack<DefUseChain.DefUseNode> stackDFS, Set<DefUseChain.DefUseNode> visitedNode,
			DefUseChain.DefUseNode duNode) {
		for (DefUseChain.DefUseNode node : duNode.getChildren()) {
			if (!visitedNode.contains(node)) {
				searchTaintRetrunValueDFS(stackDFS, visitedNode, node);
			}
		}
	}

	public int getTotal_e_count() {
		return 0;
	}

	public int getTotal_pe_count() {
		return 0;
	}

}
