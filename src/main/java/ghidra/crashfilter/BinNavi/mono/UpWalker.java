package ghidra.crashfilter.BinNavi.mono;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.crashfilter.BinNavi.mono.interfaces.IGraphWalker;

public class UpWalker implements IGraphWalker<InstructionGraphNode, WalkInformation>{
	 @Override
	  public List<InstructionGraphNode> getInfluenced(final InstructionGraphNode node) {
	    // Preconditions.checkNotNull(node, "Error: node argument can not be null");

	    // When walking upwards, the influenced nodes of a node
	    // are the parents of the node.

	    return node.getIncomingEdges()
	            .stream()
	            .map(InstructionGraphEdge::getSource)
	            .collect(Collectors.toList());
	  }

	  @Override
	  public List<InfluencingInstructionNode> getInfluencing(final InstructionGraphNode node) {
	    // Preconditions.checkNotNull(node, "Error: node argument can not be null");

	    // When walking upwards, the influencing nodes of a node
	    // are the children of the node.

	    return node.getOutgoingEdges()
	            .stream()
	            .map(edge -> new InfluencingInstructionNode(edge.getTarget(), new WalkInformation(edge)))
	            .collect(Collectors.toList());
	  }
}
