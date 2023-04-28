package ghidra.crashfilter.BinNavi.mono.interfaces;

import java.util.List;

public interface ILatticeGraph<GraphNode> {
	List<GraphNode> getNodes();
}