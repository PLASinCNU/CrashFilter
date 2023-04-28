package ghidra.crashfilter.memory.env;

import java.util.List;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingState;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILattice;

public class EnvLattice implements ILattice<EnvLatticeElement, Object> {

	@Override
	public EnvLatticeElement combine(List<IInfluencingState<EnvLatticeElement, Object>> states) {
		EnvLatticeElement combinedState = new EnvLatticeElement();

		for (IInfluencingState<EnvLatticeElement, Object> state : states) {
			combinedState.combine(state.getElement());
		}

		return combinedState;
	}

}
