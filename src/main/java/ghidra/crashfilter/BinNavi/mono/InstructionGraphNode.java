package ghidra.crashfilter.BinNavi.mono;

import java.util.ArrayList;
import java.util.List;

import ghidra.graph.GVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class InstructionGraphNode implements GVertex {
	private final PcodeOp m_pcode;
	private final Address addr;
	private final List<InstructionGraphEdge> outgoingEdges = new ArrayList<>();

	/**
	 * Incoming edges of the node.
	 */
	private final List<InstructionGraphEdge> incomingEdges = new ArrayList<>();
	private boolean isEnd = false;

	public PcodeOp getPcode() {
		return m_pcode;
	}

	public InstructionGraphNode(PcodeOp m_pcode, Address addr) {
		super();
		this.m_pcode = m_pcode;
		this.addr = addr;
	}

	public List<InstructionGraphNode> getChildren() {
		final List<InstructionGraphNode> children = new ArrayList<InstructionGraphNode>();

		for (final InstructionGraphEdge edge : outgoingEdges) {
			children.add(edge.getTarget());
		}

		return children;
	}

	public List<InstructionGraphNode> getParents() {
		final List<InstructionGraphNode> parents = new ArrayList<InstructionGraphNode>();

		for (final InstructionGraphEdge edge : incomingEdges) {
			parents.add(edge.getSource());
		}

		return parents;
	}

	public static void link(final InstructionGraphNode source, final InstructionGraphNode target,
			final InstructionGraphEdge edge) {

		source.outgoingEdges.add(edge);
		target.incomingEdges.add(edge);
	}

	public List<InstructionGraphEdge> getOutgoingEdges() {
		// TODO return an unmodifiable iterator.
		return new ArrayList<InstructionGraphEdge>(outgoingEdges);
	}

	public List<InstructionGraphEdge> getIncomingEdges() {
		// TODO return an unmodifiable iterator.
		return new ArrayList<InstructionGraphEdge>(incomingEdges);
	}

	public boolean isEnd() {
		return isEnd;
	}

	public void setEnd(boolean isEnd) {
		this.isEnd = isEnd;
	}
	public Address getAddr() {
		return addr;
	}
	public String toString() {
		return "Addr"+ addr.toString()+" "+ m_pcode.toString()+", incoming edges's number : "+incomingEdges.size(); 
	}
}
