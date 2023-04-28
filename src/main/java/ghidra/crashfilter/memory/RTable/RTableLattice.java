package ghidra.crashfilter.memory.RTable;

import java.util.List;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingState;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILattice;

public class RTableLattice implements ILattice<RTableLatticeElement, Object> {

	@Override
	public RTableLatticeElement combine(List<IInfluencingState<RTableLatticeElement, Object>> states) {
		RTableLatticeElement combinedState = new RTableLatticeElement();

		// Union all the predecessor's state
		for (IInfluencingState<RTableLatticeElement, Object> state : states) {
			combinedState.combine(state.getElement());
		}

		return combinedState;
	}

}
