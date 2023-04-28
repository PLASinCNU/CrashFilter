package ghidra.crashfilter.memory.mloc;

import ghidra.crashfilter.memory.interfaces.IValue;

public class Symbol_Bottom implements IValue {
	// Bottom Symbol
	private static Symbol_Bottom SB = null;

	private Symbol_Bottom() {
	}

	public static Symbol_Bottom getSymbolBottom() {
		if (SB == null) {
			SB = new Symbol_Bottom();
			return SB;
		}
		return SB;

	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "[Bottom]";
	}

}
