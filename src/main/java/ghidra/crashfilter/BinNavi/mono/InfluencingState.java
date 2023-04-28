package ghidra.crashfilter.BinNavi.mono;

import ghidra.crashfilter.BinNavi.mono.interfaces.IInfluencingState;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public class InfluencingState<LatticeElement extends ILatticeElement<LatticeElement>, ObjectType>
		implements IInfluencingState<LatticeElement, ObjectType> {
	private final LatticeElement element;

	private final ObjectType object;

	public InfluencingState(final LatticeElement element, final ObjectType object) {
		this.element = element;
		this.object = object;
	}

	@Override
	public LatticeElement getElement() {
		return element;
	}

	@Override
	public ObjectType getObject() {
		return object;
	}

	@Override
	public String toString() {
		return element.toString();
	}
}
