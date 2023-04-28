package ghidra.crashfilter.memory.interfaces;

public interface IValue {
	// MLoc or Val
	@Override
	public int hashCode();

	@Override
	public boolean equals(Object o);
}
