package ghidra.crashfilter.BinNavi.mono;

import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public interface ITransformationProvider<GraphNode, LatticeElement extends ILatticeElement<LatticeElement>> {
	  /**
	   * Transforms a lattice element into a new element.
	   * 
	   * @param node The node that controls the transformation.
	   * @param currentState The current state of the node.
	   * @param inputState The combined state of the influencing nodes.
	   * 
	   * @return The transformed lattice element.
	   */
	  LatticeElement transform(GraphNode node, LatticeElement currentState, LatticeElement inputState);
}
