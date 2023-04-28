package ghidra.crashfilter.BinNavi.mono;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.base.Preconditions;

import ghidra.crashfilter.BinNavi.mono.interfaces.IGraphWalker;
import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingState;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILattice;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.BinNavi.mono.interfaces.IMonotoneDebugger;

public class MonotoneSolver<GraphNode, LatticeElement extends ILatticeElement<LatticeElement>, ObjectType, Lattice extends ILattice<LatticeElement, ObjectType>> {
	private final ILatticeGraph<GraphNode> graph;
	private final Lattice lattice;
	private final IStateVector<GraphNode, LatticeElement> state;
	private final ITransformationProvider<GraphNode, LatticeElement> transformationList;
	private final IGraphWalker walker;
	private final IMonotoneDebugger debugger;

	/**
	 * Creates a new instance of a monotone solver.
	 * 
	 * @param graph                  Graph that is being worked on.
	 * @param lattice                Lattice structure that provides the method to
	 *                               merge states.
	 * @param startVector            Initial state vector.
	 * @param transformationProvider Transforms the state vector during each step of
	 *                               the algorithm.
	 * @param walker                 Specifies how to walk through the graph.
	 * @param debugger               Optional debugger that receives debugging
	 *                               information while the monotone framework is
	 *                               running.
	 */
	public MonotoneSolver(final ILatticeGraph<GraphNode> graph, final Lattice lattice,
			final IStateVector<GraphNode, LatticeElement> startVector,
			final ITransformationProvider<GraphNode, LatticeElement> transformationProvider,
			final IGraphWalker walker, final IMonotoneDebugger debugger) {
		Preconditions.checkNotNull(graph, "Error: Graph argument can not be null");
		Preconditions.checkNotNull(lattice, "Error: Lattice argument can not be null");
		Preconditions.checkNotNull(startVector, "Error: Start vector argument can not be null");
		Preconditions.checkNotNull(transformationProvider, "Error: Transformation list argument can not be null");

		final List<GraphNode> nodes = graph.getNodes();

		Preconditions.checkArgument(nodes.size() == startVector.size(), String
				.format("Error: Invalid start vector (%d states for %d nodes)", startVector.size(), nodes.size()));

		for (final GraphNode node : nodes) {
			Preconditions.checkArgument(startVector.hasState(node),
					"Error: Node " + node + " does not have a state in the initial state vector");
		}

		this.graph = graph;
		this.lattice = lattice;
		this.state = startVector;
		this.transformationList = transformationProvider;
		this.walker = walker;
		this.debugger = debugger;
	}

	/**
	 * Returns a list of current states associated with a list of given graph nodes.
	 * 
	 * @param nodes The graph nodes whose states are determined.
	 * @return The states of the given graph nodes.
	 */
	private List<IInfluencingState<LatticeElement, ObjectType>> getStates(
			final List<? extends IInfluencingNode<GraphNode, ObjectType>> nodes) {
		return nodes.stream()
				.map(node -> new InfluencingState<> (state.getState(node.getNode()), node.getObject()))
				.collect(Collectors.toList());
		//return (List<IInfluencingState<LatticeElement, ObjectType>>) result;
	}

	/**
	 * Transform the current state into the new state. We iterate over all entries
	 * in the state vector that need updating and transform them according to the
	 * defined transformation method.
	 * 
	 * @param nodesToUpdate Nodes which must be considered in this transformation
	 *                      step.
	 */
	private void transformState(final Set<GraphNode> nodesToUpdate) {
		final StateVector<GraphNode, LatticeElement> newState = new StateVector<>();

		final Set<GraphNode> newNodesToUpdate = new LinkedHashSet<>();

		for (final GraphNode node : nodesToUpdate) {
			final List<IInfluencingState<LatticeElement, ObjectType>> influencingStates = getStates(
					walker.getInfluencing(node));

			final LatticeElement combinedState = lattice.combine(influencingStates);

			final LatticeElement transformedState = transformationList.transform(node, state.getState(node),
					combinedState);

			newState.setState(node, transformedState);

			if (debugger != null) {
				debugger.updatedState(node, influencingStates, transformedState);
			}

			// State has changed since the last iteration => We need another iteration with
			// the
			// nodes that are influenced by this state change.
			if (!newState.getState(node).equals(state.getState(node))) {
				newNodesToUpdate.addAll(walker.getInfluenced(node));
			}

			if (newState.getState(node).lessThan(state.getState(node))) {
				throw new IllegalStateException("Non-monotone transformation detected");
			}
		}

		updateCurrentState(newState);

		if (debugger != null) {
			debugger.updatedState(state);
		}

		nodesToUpdate.clear();
		nodesToUpdate.addAll(newNodesToUpdate);
	}

	/**
	 * Copies the given state vector into the current state vector.
	 * 
	 * @param newState The state vector to copy.
	 */
	private void updateCurrentState(final StateVector<GraphNode, LatticeElement> newState) {
		for (final GraphNode node : newState) {
			state.setState(node, newState.getState(node));
		}
	}

	/**
	 * Run the actual code analysis. Starting from the initial state vector, iterate
	 * the transformation until a fixpoint is reached. Depending on your analysis,
	 * your transformations and the program you are analyzing, it is conceivable
	 * that this will iterate for a long while. If your lattice is infinite and not
	 * noetherian (e.g. doesn't fulfill the 'all ascending chains stabilize'), this
	 * might not terminate.
	 * 
	 * @return The fixpoint state.
	 */
	public IStateVector<GraphNode, LatticeElement> solve() {
		final HashSet<GraphNode> nodesToUpdate = new LinkedHashSet<>(graph.getNodes());

		while (!nodesToUpdate.isEmpty()) {
			transformState(nodesToUpdate);
		}

		return state;
	}
}
