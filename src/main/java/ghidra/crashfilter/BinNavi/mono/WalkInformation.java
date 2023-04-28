package ghidra.crashfilter.BinNavi.mono;

public class WalkInformation {
	private final InstructionGraphEdge m_edge;

	public WalkInformation(final InstructionGraphEdge edge) {
		m_edge = edge;
	}

	public InstructionGraphEdge getEdge() {
		return m_edge;
	}
}
