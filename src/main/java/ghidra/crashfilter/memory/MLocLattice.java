package ghidra.crashfilter.memory;



import java.util.List;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingState;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILattice;

public class MLocLattice implements ILattice<MLocLatticeElement, Object> {
	


	@Override
	public MLocLatticeElement combine(List<IInfluencingState<MLocLatticeElement, Object>> states) {
		MLocLatticeElement combinedState = new MLocLatticeElement();
		for ( IInfluencingState<MLocLatticeElement, Object> state : states ){
			combinedState.combine(state.getElement());
		}
		return combinedState;
	}


}
