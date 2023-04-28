package ghidra.crashfilter.BinNavi.mono;

public interface IStateVector <GraphNode, LatticeElement> extends Iterable<GraphNode>{
	  LatticeElement getState(GraphNode node);

	  boolean hasState(GraphNode node);

	  void setState(GraphNode node, LatticeElement element);

	  int size();
}
