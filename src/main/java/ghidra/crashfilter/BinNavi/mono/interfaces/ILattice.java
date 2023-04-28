package ghidra.crashfilter.BinNavi.mono.interfaces;

import java.util.List;
public interface ILattice<LatticeElement extends ILatticeElement<LatticeElement>, ObjectType> {
	LatticeElement combine(List<IInfluencingState<LatticeElement, ObjectType>> states);
	
}
