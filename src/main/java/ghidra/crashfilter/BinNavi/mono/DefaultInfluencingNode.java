package ghidra.crashfilter.BinNavi.mono;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingNode;

public final class DefaultInfluencingNode<GraphNode, ObjectType> implements IInfluencingNode<GraphNode, ObjectType> {
	/**
	 * The influencing graph node.
	 */
	private final GraphNode node;

	/**
	 * Creates a new influencing node object.
	 *
	 * @param node The influencing graph node.
	 */
	public DefaultInfluencingNode(final GraphNode node) {
		this.node = node;
	}

	@Override
	public GraphNode getNode() {
		return node;
	}

	@Override
	public ObjectType getObject() {
		return null;
	}
}