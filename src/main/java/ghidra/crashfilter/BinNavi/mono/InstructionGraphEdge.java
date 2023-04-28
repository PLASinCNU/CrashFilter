package ghidra.crashfilter.BinNavi.mono;

import ghidra.graph.GEdge;
import ghidra.program.model.pcode.PcodeOp;

public class InstructionGraphEdge implements GEdge<InstructionGraphNode> {

	private InstructionGraphNode source;
	private InstructionGraphNode target;

	@Override
	public InstructionGraphNode getStart() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public InstructionGraphNode getEnd() {
		// TODO Auto-generated method stub
		return null;
	}

	public InstructionGraphEdge(InstructionGraphNode source, InstructionGraphNode target) {
		super();
		this.source = source;
		this.target = target;
	}


	public InstructionGraphNode getSource() {
		return this.source;
	}

	// ESCA-JAVA0059: Required for the documentation.
	// ! The target node of the edge.
	/**
	 * Returns the target node of the edge.
	 *
	 * @return The target node of the edge.
	 */
	public InstructionGraphNode getTarget() {
		return this.target;
	}

}
