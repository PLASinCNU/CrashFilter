package ghidra.crashfilter.dataflow;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import ghidra.crashfilter.BinNavi.mono.DefaultStateVector;
import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphEdge;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.helper.CrashSourceAdder;
import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.helper.InterProcedureMode;
import ghidra.crashfilter.helper.PcodeResolver;
import ghidra.crashfilter.helper.VariableFinder;
import ghidra.program.model.address.Address;

public class ReachingDefinition {
	private ILatticeGraph<InstructionGraphNode> graph;

	private List<Address> crashAddrs = null;
	// VariableFinder deleted.
	private VariableFinder vf;

	public ReachingDefinition(ILatticeGraph<InstructionGraphNode> graph, List<Address> crashAddrs, VariableFinder vf) {
		this.vf = vf;
		this.graph = graph;
		this.crashAddrs = crashAddrs;
	}

	public IStateVector<InstructionGraphNode, DefLatticeElement> initializeState(
			ILatticeGraph<InstructionGraphNode> graph) /* throws MLocException */ {
		// 초기 상태 초기화
		// 초기 상태는 empty set으로 시작하기 때문에 kill set 외에 따로 초기화 하지 않음
		DefLatticeElement state;
		IStateVector<InstructionGraphNode, DefLatticeElement> startVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();
		IStateVector<InstructionGraphNode, DefLatticeElement> startVectorAfter = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

		// gathering the kill set of each instruction
		// After memory access analysis, we have to use the results.

		for (int i = 0; i < graph.getNodes().size(); i++) {
			DefLatticeElement stateI = null;
			InstructionGraphNode defInst1 = graph.getNodes().get(i);
			if (startVectorAfter.hasState(defInst1))
				stateI = startVectorAfter.getState(defInst1);
			else
				stateI = new DefLatticeElement();
			for (int j = i; j < graph.getNodes().size(); j++) {
				InstructionGraphNode defInst2 = graph.getNodes().get(j);
				DefLatticeElement stateJ = null;
				if (startVector.hasState(defInst1))
					stateJ = startVectorAfter.getState(defInst2);
				else
					stateJ = new DefLatticeElement();

				if (PcodeResolver.isSameDefinition(defInst1, defInst2)) {
					// pcode 관련 다시 정의
					stateI.insertKill(defInst2);
					stateJ.insertKill(defInst1);
				}
				startVectorAfter.setState(defInst2, stateJ);
			}
			startVectorAfter.setState(defInst1, stateI);
		}

		for (InstructionGraphNode defInst1 : graph.getNodes()) {
			state = new DefLatticeElement();
			for (InstructionGraphNode defInst2 : graph.getNodes()) {
				// 킬셋 초기화
				// Some time later we will add VSA and have to add some code for
				// new kill set considering memory
				if (PcodeResolver.isSameDefinition(defInst1, defInst2)) {
					state.insertKill(defInst2);
				}
			}
			startVector.setState(defInst1, state);

		}
		// isEqual(startVectorAfter, startVector);
		return startVector;
	}

	private void isEqual(IStateVector<InstructionGraphNode, DefLatticeElement> startVectorAfter,
			IStateVector<InstructionGraphNode, DefLatticeElement> startVector) {
		if (startVectorAfter.size() != startVector.size()) {
			System.out.println("Not Equals your code: StartVectorAfter != startVector");
		}
		for (InstructionGraphNode inst : startVector) {
			if (!startVectorAfter.hasState(inst)) {
				System.out.println("Not Equals your codeb n    : no inst");
			}
			DefLatticeElement state1 = startVector.getState(inst);
			DefLatticeElement state2 = startVectorAfter.getState(inst);
			if (state1.getKillList().size() != state2.getKillList().size()) {
				System.out.println("Not Equals your code not equal: not equal kill list");
			}

		}
		System.out.println("RDA ddddddd");
	}

	public IStateVector<InstructionGraphNode, DefLatticeElement> runRDAnalysis(InterProcedureMode analysisMode)
	/* throws MLocException */ {

		IStateVector<InstructionGraphNode, DefLatticeElement> startVector;
		IStateVector<InstructionGraphNode, DefLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

		startVector = initializeState(graph);

		Map<Address, InstructionGraphNode> toBeAddedSrcNAddresses;
		toBeAddedSrcNAddresses = CrashSourceAdder.getSrcNAddress(graph, crashAddrs, analysisMode, vf);

		endVector = runRD(startVector, toBeAddedSrcNAddresses);
		return endVector;
	}

	private IStateVector<InstructionGraphNode, DefLatticeElement> runRD(
			IStateVector<InstructionGraphNode, DefLatticeElement> startVector,
			Map<Address, InstructionGraphNode> toBeAddedSrcNAddresses) {

		boolean realChanged = false;
		int count = 0;
		boolean changed = true;
		List<InstructionGraphNode> nodes = graph.getNodes();
		IStateVector<InstructionGraphNode, DefLatticeElement> vector = startVector;
		IStateVector<InstructionGraphNode, DefLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

		while (changed) {
			for (InstructionGraphNode node : nodes) {
				List<InstructionGraphNode> preds = getPredNodes(node);

				if (hasNoPred(preds)) {
					settingEntry(endVector, node);
				} else {

					DefLatticeElement transformedState = new DefLatticeElement();

					DefLatticeElement currentState = applyMeetOperation(vector, node, preds, transformedState);

					// transfer function
					// binnavi의 인터페이스보고 같은 형태로 되게 하기
					// IN: transformState
					// currentState: instList는 previous out, KILLList는 KILL
					transformState(node, transformedState, currentState);

					if (isInsertAddress(toBeAddedSrcNAddresses, node)) {
						InstructionGraphNode srcNode = toBeAddedSrcNAddresses
								.get(node.getAddr());
						transformedState.insertInst(srcNode);
					}

					endVector.setState(node, transformedState);
				}
			}

			changed = isChanged(vector, endVector);

			vector = endVector;
			System.out.println("changed : " + changed);

		}

		return endVector;
	}

	private boolean isInsertAddress(Map<Address, InstructionGraphNode> toBeAddedSrcNAddresses, InstructionGraphNode node) {
		return toBeAddedSrcNAddresses.containsKey(node.getAddr());
	}

	private boolean isChanged(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
			IStateVector<InstructionGraphNode, DefLatticeElement> endVector) {
		return !vector.equals(endVector);
	}

	private void transformState(InstructionGraphNode node, DefLatticeElement transformedState,
			DefLatticeElement currentState) {
		// transformedState = IN - KILL
		transformedState.removeAllInstList(currentState.getKillList());

		// transformedState = (IN- KILL) + GEN
		if (!(PcodeResolver.resolveReilInstructionDest(node).isEmpty())) {

			transformedState.insertInst(node);
		}
		// new transformedState의 KILL 초기화
		transformedState.unionKillList(currentState.getKillList());

		// 라티스 fixed point 성질 확인
		if (transformedState.lessThan(currentState)) {
			System.out.println("Error : ReachingDefinition - runRD - lessThan");
		}
	}

	private DefLatticeElement applyMeetOperation(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
			InstructionGraphNode node, List<InstructionGraphNode> preds, DefLatticeElement transformedState) {
		DefLatticeElement currentState = vector.getState(node);
		// 변수이름 바꾸기
		//
		DefLatticeElement inputElement = unionPred(vector, preds);

		transformedState.unionInstList(inputElement.getInstList());
		return currentState;
	}

	private void settingEntry(IStateVector<InstructionGraphNode, DefLatticeElement> endVector,
			InstructionGraphNode node) {
		DefLatticeElement entry = new DefLatticeElement();
		entry.setInst(node);
		entry.instList = new HashSet<InstructionGraphNode>();
		entry.insertInst(node);
		entry.inst = node;
		endVector.setState(node, entry);
	}

	private boolean hasNoPred(List<InstructionGraphNode> preds) {
		return preds.size() == 0;
	}

	private DefLatticeElement unionPred(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
			List<InstructionGraphNode> preds) {
		if (hasNoPred(preds)) {
			return null;
		} else if (preds.size() == 1) {
			return vector.getState(preds.get(0));
		} else {
			DefLatticeElement mergedElement = new DefLatticeElement();
			List<DefLatticeElement> predElements = new ArrayList<DefLatticeElement>();
			for (InstructionGraphNode pred : preds) {
				predElements.add(vector.getState(pred));
			}
			return mergedElement.transLatticeElement(predElements);
		}
	}

	private List<InstructionGraphNode> getPredNodes(InstructionGraphNode node) {
		List<InstructionGraphEdge> edges = node.getIncomingEdges();
		List<InstructionGraphNode> nodes = new ArrayList<InstructionGraphNode>();
		for (InstructionGraphEdge edge : edges) {
			nodes.add(edge.getSource());
		}
		return nodes;
	}

	public void printRD(IStateVector<InstructionGraphNode, DefLatticeElement> endVector) {

		DefLatticeElement state = null;
		for (InstructionGraphNode inst : graph.getNodes()) {
			state = endVector.getState(inst);
			GhidraConsolePrint.println("instruction : ");
			GhidraConsolePrint.println(inst.getPcode().toString());
			GhidraConsolePrint.println("\n");

			for (InstructionGraphNode reachingInst : state.getInstList()) {
				GhidraConsolePrint.println("\t" + reachingInst.getPcode().toString());
				GhidraConsolePrint.println("\n");
			}
		}
	}

	private IStateVector<InstructionGraphNode, DefLatticeElement> vectorClone(
			IStateVector<InstructionGraphNode, DefLatticeElement> orig) {
		IStateVector<InstructionGraphNode, DefLatticeElement> clone = new DefaultStateVector<>();
		for (InstructionGraphNode node : this.graph.getNodes()) {
			DefLatticeElement cloneElement = new DefLatticeElement();
			cloneElement.unionInstList(orig.getState(node).getInstList());
			clone.setState(node, cloneElement);
		}
		return orig;
	}
}
