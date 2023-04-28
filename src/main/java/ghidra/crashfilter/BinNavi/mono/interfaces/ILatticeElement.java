package ghidra.crashfilter.BinNavi.mono.interfaces;

public interface ILatticeElement<LatticeElement extends ILatticeElement<?>> {
	boolean equals(LatticeElement rhs);

	boolean lessThan(LatticeElement rhs);
}
