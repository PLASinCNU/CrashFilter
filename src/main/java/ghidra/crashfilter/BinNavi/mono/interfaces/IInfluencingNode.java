package ghidra.crashfilter.BinNavi.mono.interfaces;

public interface IInfluencingNode <GraphNode, ObjectType>{
	  GraphNode getNode();

	  ObjectType getObject();
}
