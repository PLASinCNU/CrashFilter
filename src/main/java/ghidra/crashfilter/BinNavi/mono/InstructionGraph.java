package ghidra.crashfilter.BinNavi.mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.PseudoInstruction;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.helper.PseudoProvider;
import ghidra.graph.GDirectedGraph;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.BlockGraph;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.FlowType;

public class InstructionGraph
		implements GDirectedGraph<InstructionGraphNode, InstructionGraphEdge>, ILatticeGraph<InstructionGraphNode> {

	@Override
	public String toString() {
		return "InstructionGraph [nodes=" + nodes.size() + ", edges=" + edges.size() + "]";
	}
	final private Collection<InstructionGraphNode> nodes = new ArrayList<InstructionGraphNode>();
	final private Collection<InstructionGraphEdge> edges = new ArrayList<InstructionGraphEdge>();
	final private Map<Address, ArrayList<InstructionGraphNode>> addrToInsts = new HashMap<>();
	@Override
	public boolean addVertex(InstructionGraphNode v) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean removeVertex(InstructionGraphNode v) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void removeVertices(Iterable<InstructionGraphNode> vertices) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addEdge(InstructionGraphEdge e) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean removeEdge(InstructionGraphEdge e) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void removeEdges(Iterable<InstructionGraphEdge> edges) {
		// TODO Auto-generated method stub

	}

	@Override
	public InstructionGraphEdge findEdge(InstructionGraphNode start, InstructionGraphNode end) {
		// TODO Auto-generated method stub
		return null;
	}

	public Collection<InstructionGraphNode> getVertices() {
		// TODO Auto-generated method stub
		return nodes;
	}

	@Override
	public Collection<InstructionGraphEdge> getEdges() {
		// TODO Auto-generated method stub
		return this.edges;
	}

	@Override
	public boolean containsVertex(InstructionGraphNode v) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean containsEdge(InstructionGraphEdge e) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean containsEdge(InstructionGraphNode from, InstructionGraphNode to) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isEmpty() {
		// TODO Auto-generated method stub
		return this.nodes.isEmpty();
	}

	@Override
	public int getVertexCount() {
		// TODO Auto-generated method stub
		
		return this.nodes.size();
	}

	@Override
	public int getEdgeCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Collection<InstructionGraphEdge> getInEdges(InstructionGraphNode v) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public GDirectedGraph<InstructionGraphNode, InstructionGraphEdge> copy() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public GDirectedGraph<InstructionGraphNode, InstructionGraphEdge> emptyCopy() {
		// TODO Auto-generated method stub
		return null;
	}

	public static InstructionGraph create(final Function func) {
		InstructionGraph result = new InstructionGraph();
		final Collection<InstructionGraphNode> nodes = result.getVertices();
		final Collection<InstructionGraphEdge> edges = result.getEdges();
		final Map<Address, ArrayList<InstructionGraphNode>> addrToInsts = result.getAddrToInsts();
		final HashMap<Address, PseudoInstruction> addrToInst = new HashMap<Address, PseudoInstruction>();
		final HashMap<Address, Set<InstructionGraphNode>> preds = new HashMap<Address, Set<InstructionGraphNode>>();
		final HashMap<String, InstructionGraphNode> pcodeFromIgn = new HashMap<String, InstructionGraphNode>();

		PseudoProvider pp = PseudoProvider.getPseudoProvider(func.getProgram());
		ArrayList<PseudoInstruction> pSeudos = pp.getPseudos(func);
		
		for (PseudoInstruction pSeudo : pSeudos) {
			ArrayList<InstructionGraphNode> pcodes = new ArrayList<InstructionGraphNode>();
			for (int i = 0 ; i < pSeudo.getPcode().length; i++) {
				PcodeOp pcode = pSeudo.getPcode()[i];
				InstructionGraphNode ign = new InstructionGraphNode(pcode, pSeudo.getAddress());
				String key = PseudoProvider.getAppendAddressIndex(pSeudo.getAddress(), i);
				pcodes.add(ign);
				pcodeFromIgn.put(key , ign);
				nodes.add(ign);
			}
			addrToInst.put(pSeudo.getAddress(), pSeudo);
			addrToInsts.put(pSeudo.getAddress(), pcodes);
		}
		for (PseudoInstruction pSeudo : pSeudos) {
			// pSeudo.getFlows()

			Address[] succs = pSeudo.getFlows();
			PcodeOp[] pcodes = pSeudo.getPcode();
			String key = PseudoProvider.getAppendAddressIndex(pSeudo.getAddress(), 0);

			InstructionGraphNode source = pcodeFromIgn.get(key);
			for(int i = 1 ; i< pcodes.length; i++){
				key = PseudoProvider.getAppendAddressIndex(pSeudo.getAddress(), i);
				InstructionGraphNode dest = pcodeFromIgn.get(key);
				InstructionGraphEdge ige = new InstructionGraphEdge(source, dest);
				InstructionGraphNode.link(source, dest, ige);
				edges.add(ige);

				source = dest;
			}
			key = PseudoProvider.getAppendAddressIndex(pSeudo.getAddress(), pcodes.length-1);

			source = pcodeFromIgn.get(key);
			for (Address succ : succs) {
				PseudoInstruction succPSeudo = addrToInst.get(succ);
				if(succPSeudo == null) continue; // succPSeudo is other function 
				
				key = PseudoProvider.getAppendAddressIndex(succPSeudo.getAddress(), 0);

				InstructionGraphNode dest = pcodeFromIgn.get(key);
				InstructionGraphEdge ige = new InstructionGraphEdge(source, dest);
				InstructionGraphNode.link(source, dest, ige);
				edges.add(ige);
			}
		}
		GhidraConsolePrint.println(result.toString());
		return result;
	}

	public Map<Address, ArrayList<InstructionGraphNode>> getAddrToInsts() {
		return addrToInsts;
	}

	public InstructionGraph() {
		super();
		// TODO Auto-generated constructor stub
	}

	@Override
	public Collection<InstructionGraphEdge> getOutEdges(InstructionGraphNode v) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<InstructionGraphNode> getNodes() {
		// TODO Auto-generated method stub
		return (List<InstructionGraphNode>) nodes;
	}
	public List<InstructionGraphNode> getNodes(Address addr){
		return this.addrToInsts.get(addr);
	}
}
