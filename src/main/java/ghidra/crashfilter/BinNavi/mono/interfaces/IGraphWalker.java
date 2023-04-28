package ghidra.crashfilter.BinNavi.mono.interfaces;

import java.util.List;

public interface IGraphWalker<GraphNode, ObjectType> {
	/**
	 * Returns a list of nodes that contains all nodes that are influenced by state
	 * changes in the passed node.
	 * 
	 * @param node The start node.
	 * 
	 * @return List of nodes that are influenced by the passed node.
	 */
	List<GraphNode> getInfluenced(GraphNode node);

	/**
	 * Returns a list of nodes that contains all nodes that are necessary to
	 * determine the state of the passed node.
	 * 
	 * @param node The start node.
	 * 
	 * @return List of nodes that influence the passed node.
	 */
	List<? extends IInfluencingNode<GraphNode, ObjectType>> getInfluencing(GraphNode node);
}
