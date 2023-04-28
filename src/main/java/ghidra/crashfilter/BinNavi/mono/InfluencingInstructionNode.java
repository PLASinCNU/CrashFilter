package ghidra.crashfilter.BinNavi.mono;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingNode;

public class InfluencingInstructionNode implements IInfluencingNode<InstructionGraphNode, WalkInformation> {
	private final InstructionGraphNode node;
	private final WalkInformation information;

	public InfluencingInstructionNode(final InstructionGraphNode node, final WalkInformation information) {
		this.node = node;
		this.information = information;
	}

	@Override
	public InstructionGraphNode getNode() {
		return node;
	}

	@Override
	public WalkInformation getObject() {
		return information;
	}
}
