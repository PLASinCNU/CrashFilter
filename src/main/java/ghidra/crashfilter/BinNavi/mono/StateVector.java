package ghidra.crashfilter.BinNavi.mono;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.base.Preconditions;

import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public final class StateVector<GraphNode, LatticeElement extends ILatticeElement<LatticeElement>>
		implements IStateVector<GraphNode, LatticeElement>, Iterable<GraphNode> {
	private final Map<GraphNode, LatticeElement> mapping = new LinkedHashMap<>();

	/**
	 * Returns the state of a node.
	 * 
	 * @param node The node in question.
	 * 
	 * @return The state of the node.
	 */
	@Override
	public LatticeElement getState(final GraphNode node) {
		return mapping.get(Preconditions.checkNotNull(node, "Error: node argument can not be null"));
	}

	/**
	 * Determines whether a given node has a known state.
	 * 
	 * @param node The node in question.
	 * 
	 * @return True, if the node has a known state. False, otherwise.
	 */
	@Override
	public boolean hasState(final GraphNode node) {
		return mapping.containsKey(Preconditions.checkNotNull(node, "Error: node argument can not be null"));
	}

	@Override
	public Iterator<GraphNode> iterator() {
		return mapping.keySet().iterator();
	}

	/**
	 * Sets the state of a node.
	 * 
	 * @param node    The node in question.
	 * @param element The new state of the node.
	 */
	@Override
	public void setState(final GraphNode node, final LatticeElement element) {
		Preconditions.checkNotNull(node, "Error: node argument can not be null");
		Preconditions.checkNotNull(element, "Error: element argument can not be null");
		mapping.put(node, element);
	}

	/**
	 * Returns the number of elements in the vector.
	 * 
	 * @return The number of elements in the vector.
	 */
	@Override
	public int size() {
		return mapping.size();
	}

	@Override
	public String toString() {

		return mapping.entrySet().stream().map(entry -> entry.getKey() + " -> " + entry.getValue())
				.collect(Collectors.joining("\n", "[\n", "\n]"));
	}
}
