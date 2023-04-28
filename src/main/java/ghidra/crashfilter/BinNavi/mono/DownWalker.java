package ghidra.crashfilter.BinNavi.mono;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.crashfilter.BinNavi.mono.interfaces.IGraphWalker;

public class DownWalker implements IGraphWalker<InstructionGraphNode, WalkInformation>  {
	  @Override
	  public List<InstructionGraphNode> getInfluenced(final InstructionGraphNode node) {
	   // Preconditions.checkNotNull(node, "Error: node argument can not be null");

	    // When walking downwards, the influenced nodes of a node
	    // are its children.

	    return node.getOutgoingEdges()
	            .stream()
	            .map(InstructionGraphEdge::getTarget)
	            .collect(Collectors.toList());
	  }

	  @Override
	  public List<InfluencingInstructionNode> getInfluencing(final InstructionGraphNode node) {
	    // Preconditions.checkNotNull(node, "Error: node argument can not be null");

	    // When walking downwards, the influencing nodes of a node
	    // are its parents.

	    return node.getIncomingEdges()
	            .stream()
	            .map(edge -> new InfluencingInstructionNode(edge.getSource(), new WalkInformation(edge)))
	            .collect(Collectors.toList());
	  }
}
