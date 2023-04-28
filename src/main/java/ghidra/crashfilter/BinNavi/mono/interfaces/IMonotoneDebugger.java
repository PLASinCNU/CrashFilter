package ghidra.crashfilter.BinNavi.mono.interfaces;

public interface IMonotoneDebugger {
	void updatedState(Object state);

	void updatedState(Object node, Object influencingStates, Object state);
}
