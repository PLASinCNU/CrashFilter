package ghidra.crashfilter.dataflow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import generic.stl.Pair;
import ghidra.crashfilter.BinNavi.mono.IStateVector;
import ghidra.crashfilter.BinNavi.mono.InstructionGraph;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.helper.CrashSourceAdder;
import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.helper.MemoryChecker;
import ghidra.crashfilter.helper.PcodeResolver;
import ghidra.crashfilter.memory.MLocLatticeElement;
import ghidra.crashfilter.memory.mloc.MLocException;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class DefUseChain {
	// dstUseChain : dest가 def로 정의되고, 나중에 유즈되는 곳(src)의 주소를 정의함
	private Map<InstructionGraphNode, List<InstructionGraphNode>> defUseChains = new HashMap<InstructionGraphNode, List<InstructionGraphNode>>();
	private Map<InstructionGraphNode, List<InstructionGraphNode>> useDefChains = new HashMap<InstructionGraphNode, List<InstructionGraphNode>>();
	private IStateVector<InstructionGraphNode, DefLatticeElement> RDResult;
	private ILatticeGraph<InstructionGraphNode> graph;
	private List<DefUseGraph> duGraphs = new ArrayList<DefUseGraph>();
	private IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult;
	private boolean doCrashSrcAnalysis = false; // if it is true , ver 1.2
	private Address crashPointAddress;
	private InstructionGraph defUseGraph;
	private List<InstructionGraphNode> resultSet;

	// pair first is def, pair second is use and string is operand propagated
	private Map<InstructionGraphNode, Set<Pair<InstructionGraphNode, String>>> propagateOp = new LinkedHashMap<>();
	// For Data dependence graph
	// key of ddgSrcNode is InstructionGraphNode of dst.
	//
	Set<String> ddgEdges = new HashSet<>();

	public void setMemoryResult(IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult) {
		this.mLocResult = mLocResult;
	}

	public DefUseChain(IStateVector<InstructionGraphNode, DefLatticeElement> rDResult,
			ILatticeGraph<InstructionGraphNode> graph, Address crashPointAddress, boolean doCrashSrcAnalysis) {
		this.RDResult = rDResult;
		this.graph = graph;
		this.crashPointAddress = crashPointAddress;
		this.doCrashSrcAnalysis = doCrashSrcAnalysis;
	}

	private boolean isDefUsed(InstructionGraphNode def, InstructionGraphNode use, boolean rdContain)
			throws MLocException {
		List<Varnode> destList = PcodeResolver.resolveReilInstructionDest(def);
		List<Varnode> srcList = PcodeResolver.resolveReilInstructionSrc(use);

		// if source set is empty, we don't need to check anymore
		if (srcList.isEmpty()) {
			return false;
		}
		switch (PcodeResolver.getKindInst(use)) {
		case STORE:
			switch (PcodeResolver.getKindInst(def)) {
			case STORE:
				return false;
			case OTHER:
			case LOAD:
				for (Varnode dest : destList) {
					if (dest.isRegister()) {
						if (dest.toString().equals(use.getPcode().getInput(0).toString())) {
							String ss = "Def: " + def.toString() + "Use: " + use.toString() + "\n";
							return true;
						} else
							return false;
					}
				}
			default:
				break;
			}
		case LOAD:
			switch (PcodeResolver.getKindInst(def)) {
			case STORE:
				// In case of global memory access
				// We can be aware of the position of direct memory access, so
				// we are able to consider this case

				if (PcodeResolver.isLiteralDirectAccess(use)) {
					if (PcodeResolver.isLiteralDirectAccess(def)) {
						if (use.getPcode().getInput(1).toString().equals(def.getPcode().getInput(2).toString())) {
							return true;
						} else
							return false;
					} else if (PcodeResolver.isRegisterIndirectAccess(def))
						return true;
				} else if (PcodeResolver.isRegisterIndirectAccess(use) && PcodeResolver.isLiteralDirectAccess(def)) {
					return true;
				}

				return true;
			case LOAD:
			case OTHER:
				for (Varnode dest : destList) {
					for (Varnode src : srcList) {
						if (dest.toString().equals(src.toString()))
							return true;
					}
				}
				return false;
			default:
				break;
			}
		default:
			switch (PcodeResolver.getKindInst(def)) {
			case STORE:
				return false;
			case OTHER:
				for (Varnode dest : destList) {
					for (Varnode src : srcList) {
						if (dest.isRegister() && src.isRegister()) {
							if (dest.toString().equals(src.toString())) {
								if (rdContain) {
									propagateOp.get(use).add(new Pair<>(def, dest.toString()));
								}
								return true;
							}
						}
					}
				}
			case LOAD:
				for (Varnode dest : destList) {
					for (Varnode src : srcList) {
						if (dest.isRegister() && src.isRegister()) {
							if (dest.toString().equals(src.toString())) {
								return true;
							}
						}
					}
				}
			default:
				break;
			}
		}
		return false;
	}

	// we have to add some memory related task after VSA
	public void defUseChaining(List<InstructionGraphNode> insts) throws MLocException {
		List<InstructionGraphNode> uses = null;

		int count = 0;
		int count2 = 0;

		for (InstructionGraphNode def : insts) {
			uses = new ArrayList<InstructionGraphNode>();
			for (InstructionGraphNode use : graph.getNodes()) {
				if (!this.propagateOp.containsKey(use)) {
					Set<Pair<InstructionGraphNode, String>> pairs = new HashSet<>();
					this.propagateOp.put(use, pairs);
				}
				Set<InstructionGraphNode> reachableInstList = RDResult.getState(use).getInstList();
				boolean rdContain = reachableInstList.contains(def);

				for (InstructionGraphNode node : reachableInstList) {
					if (def.getAddr().equals(node.getAddr())) {
						rdContain = true;
					}
				}

				boolean isDU = isDefUsed(def, use, rdContain);

				boolean flag = (def != use) && rdContain && isDU;

				if (flag) {
					MemoryChecker mc = new MemoryChecker();
					mc.setMLocResult(mLocResult);
					uses.add(use);

					if (mLocResult != null) {
						if (mc.differentMemoryCheckEnv(def, use)) {
							count++;
							uses.remove(use);
							// LogConsole.log(flag+" Defferent\n");
							break;
						}
						String edgeString = use.getAddr().toString() + ":" + "MEM_READ or MEM_WRITE" + ":"
								+ def.getAddr().toString();
						ddgEdges.add(edgeString);
						propagateOp.get(use).add(new Pair<>(def, "mem"));
						count2++;
					}
				}
				if (propagateOp.get(use).size() == 0)
					propagateOp.remove(use);
			}

			// Here, if there is no any use that uses the relevant def, we just
			// ignore the def
			if (!uses.isEmpty()) {
				defUseChains.put(def, uses);
			}
		}
		// LogConsole.log("disconnected : " + count + "/" + count2 + "\n");

	}

	public Map<InstructionGraphNode, Set<Pair<InstructionGraphNode, String>>> getPropagateOp() {
		return propagateOp;
	}

	public void printChain() {
		GhidraConsolePrint.println("Print Chain");
		for (Entry<InstructionGraphNode, List<InstructionGraphNode>> defUseChain : defUseChains.entrySet()) {
			GhidraConsolePrint.println("<def> : " + defUseChain.getKey().getPcode().toString()
			 + "\n");
			for (InstructionGraphNode use : defUseChain.getValue()) {
				GhidraConsolePrint.println("\t [use] : " + use.getPcode().toString() + "\n");
			}
			GhidraConsolePrint.println("\n");
		}

	}

	public Map<InstructionGraphNode, List<InstructionGraphNode>> getDefUseChains() {
		return defUseChains;
	}

	public void printDuGraph(DefUseGraph duGraph) {
		if (duGraph.getNodes().isEmpty()) {
			GhidraConsolePrint.println("graph empty!!\n");
		}

		for (DefUseNode node : duGraph.getNodes()) {
			GhidraConsolePrint.println("[Node] " + node.getInst().getPcode().toString() + " :\n");
			for (DefUseNode outgoingNode : node.getChildren()) {
				GhidraConsolePrint.println("\t" + outgoingNode.getInst().getPcode().toString() + "\n");
			}
			GhidraConsolePrint.println("\n");
		}
	}

	public List<DefUseGraph> getDuGraphs() {
		return duGraphs;
	}

	public void createDefUseGraph(InstructionGraphNode inst) {
		Map<InstructionGraphNode, DefUseNode> visitedNodes = new HashMap<InstructionGraphNode, DefUseNode>();
		DefUseGraph duGraph = new DefUseGraph();

		DefUseNode duNode = new DefUseNode(inst);
		createDefUseGraph(duGraph, visitedNodes, duNode);

		duGraphs.add(duGraph);
	}

	// using recursion for creating DEF-USE Graph
	private void createDefUseGraph(DefUseGraph duGraph, Map<InstructionGraphNode, DefUseNode> visitedNodes,
			DefUseNode duNode) {

		duGraph.addNode(duNode);
		visitedNodes.put(duNode.getInst(), duNode);

		List<InstructionGraphNode> duNodes = new ArrayList<InstructionGraphNode>();

		boolean hasDUInst = false;
		for (InstructionGraphNode inst : defUseChains.keySet()) {
			if (inst.getAddr().equals(duNode.getInst().getAddr())) {
				duNodes = defUseChains.get(inst);
				hasDUInst = true;
				break;
			}
		}

		if (hasDUInst) {

			for (InstructionGraphNode use : duNodes) {
				if (visitedNodes.containsKey(use)) {
					DefUseEdge duEdge = new DefUseEdge(duNode, visitedNodes.get(use));
					duNode.link(duNode, visitedNodes.get(use), duEdge);
					duGraph.addEdge(duEdge);
				} else {
					DefUseNode newNode = new DefUseNode(use);
					DefUseEdge duEdge = new DefUseEdge(duNode, newNode);
					duNode.link(duNode, newNode, duEdge);
					duGraph.addEdge(duEdge);
					createDefUseGraph(duGraph, visitedNodes, newNode);
				}
			}
		}

	}

	public List<InstructionGraphNode> getUseSet(List<InstructionGraphNode> insts) {
		getDeepUseSet(new HashSet<>(insts));
		return this.resultSet;
	}

	private void getDeepUseSet(Set<InstructionGraphNode> defs) {
		for (InstructionGraphNode defInstruction : defs) {
			this.getUseSet(defInstruction);
		}
	}

	private void getUseSet(InstructionGraphNode def) {
		this.resultSet.add(def);
		if (this.defUseChains.containsKey(def)) {
			for (InstructionGraphNode use : this.defUseChains.get(def)) {
				getUseSet(use);
			}
		}
	}

	public class DefUseNode {
		private InstructionGraphNode inst;
		private List<DefUseNode> children = new ArrayList<DefUseNode>();
		private List<DefUseNode> parents = new ArrayList<DefUseNode>();

		private List<DefUseEdge> incomingEdges = new ArrayList<DefUseEdge>();
		private List<DefUseEdge> outcomingEdges = new ArrayList<DefUseEdge>();

		DefUseNode(final InstructionGraphNode inst) {
			this.inst = inst;
		}

		public String toString() {
			return this.inst + "";
		}

		public InstructionGraphNode getInst() {
			return inst;
		}

		public List<DefUseNode> getChildren() {
			return children;
		}

		public List<DefUseNode> getParents() {
			return parents;
		}

		public List<DefUseEdge> getIncomingEdges() {
			return incomingEdges;
		}

		public List<DefUseEdge> getOutcomingEdges() {
			return outcomingEdges;
		}

		public void addChild(DefUseNode child) {
			children.add(child);
		}

		public void addParent(DefUseNode parent) {
			parents.add(parent);
		}

		public void addIncomingEdge(DefUseEdge incomingEdge) {
			incomingEdges.add(incomingEdge);
		}

		public void addOutComingEdge(DefUseEdge outcomingEdge) {
			outcomingEdges.add(outcomingEdge);
		}

		public void removeChild(DefUseNode child) {
			children.remove(child);
		}

		public void removeParent(DefUseNode parent) {
			parents.remove(parent);
		}

		public void removeIncomingEdge(DefUseEdge incomingEdge) {
			incomingEdges.remove(incomingEdge);
		}

		public void removeOutComingEdge(DefUseEdge outcomingEdge) {
			outcomingEdges.remove(outcomingEdge);
		}

		void link(final DefUseNode source, final DefUseNode target, final DefUseEdge edge) {
			if ((source != null) && (target != null) && (edge != null)) {
				target.addParent(source);
				source.addChild(target);
				target.addIncomingEdge(edge);
				source.addOutComingEdge(edge);
			} else
				return;
		}

		void unlink(final DefUseNode source, final DefUseNode target, final DefUseEdge edge) {
			if ((source != null) && (target != null) && (edge != null)) {
				target.removeParent(source);
				source.removeChild(target);
				target.removeIncomingEdge(edge);
				source.removeOutComingEdge(edge);
			} else
				return;
		}

	}

	@SuppressWarnings("unused")
	public class DefUseEdge {
		private DefUseNode source;
		private DefUseNode target;

		public DefUseEdge(DefUseNode source, DefUseNode target) {
			this.source = source;
			this.target = target;
		}

		public DefUseNode getSource() {
			return source;
		}

		public DefUseNode getTarget() {
			return target;
		}

		public String toString() {
			return source + "->" + target + "\n";
		}

	}

	public class DefUseGraph {
		private List<DefUseNode> nodes = new ArrayList<DefUseNode>();
		private List<DefUseEdge> edges = new ArrayList<DefUseEdge>();

		DefUseGraph() {

		}

		public List<DefUseNode> getNodes() {
			return nodes;
		}

		public List<DefUseEdge> getEdges() {
			return edges;
		}

		public void addNode(DefUseNode node) {
			nodes.add(node);
		}

		public void addEdge(DefUseEdge edge) {
			edges.add(edge);
		}

	}

}
