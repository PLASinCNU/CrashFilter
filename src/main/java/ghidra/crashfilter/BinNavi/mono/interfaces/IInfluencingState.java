package ghidra.crashfilter.BinNavi.mono.interfaces;

public interface IInfluencingState <LatticeElement extends ILatticeElement<LatticeElement>, ObjectType>{
	  LatticeElement getElement();

	  ObjectType getObject();
}
