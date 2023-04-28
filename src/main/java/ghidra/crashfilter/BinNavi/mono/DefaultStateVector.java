package ghidra.crashfilter.BinNavi.mono;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import com.google.common.base.Preconditions;

import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public class DefaultStateVector<GraphNode, LatticeElement extends ILatticeElement<LatticeElement>>
		implements IStateVector<GraphNode, LatticeElement>, Iterable<GraphNode> {
	private final Map<GraphNode, LatticeElement> mapping = new HashMap<GraphNode, LatticeElement>();

	@Override
	public final LatticeElement getState(final GraphNode node) {
		Preconditions.checkNotNull(node, "Error: node argument can not be null");
		return mapping.get(node);
	}

	@Override
	public final boolean hasState(final GraphNode node) {
		Preconditions.checkNotNull(node, "Error: node argument can not be null");
		return mapping.containsKey(node);
	}

	@Override
	public final Iterator<GraphNode> iterator() {
		return mapping.keySet().iterator();
	}

	@Override
	public final void setState(final GraphNode node, final LatticeElement element) {
		Preconditions.checkNotNull(node, "Error: node argument can not be null");
		Preconditions.checkNotNull(element, "Error: element argument can not be null");
		mapping.put(node, element);
	}

	@Override
	public final int size() {
		return mapping.size();
	}

	// ! Printable representation of the state vector.
	/**
	 * Returns a string representation of the state vector.
	 * 
	 * @return A string representation of the state vector.
	 */
	@Override
	public String toString() {
		final StringBuilder stringBuilder = new StringBuilder();

		stringBuilder.append("[\n");

		for (final Entry<GraphNode, LatticeElement> entry : mapping.entrySet()) {
			stringBuilder.append(entry.getKey() + " -> " + entry.getValue());
			stringBuilder.append('\n');
		}

		stringBuilder.append(']');

		return stringBuilder.toString();
	}
}
