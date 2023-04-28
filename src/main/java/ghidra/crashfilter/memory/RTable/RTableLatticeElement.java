package ghidra.crashfilter.memory.RTable;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public class RTableLatticeElement implements ILatticeElement<RTableLatticeElement>{
	private InstructionGraphNode inst;
	private RTable rtable;

	
	
	public RTableLatticeElement()
	{
		rtable = new RTable();
	}
	
	public void setRTable(RTable rtable)
	{
		this.rtable = rtable;
	}
	public void setInst(InstructionGraphNode inst)
	{
		this.inst = inst;
	}
	
	public RTable getRTable()
	{
		return this.rtable;
	}
	
	public void combine( RTableLatticeElement loc)
	{		
		this.inst = loc.inst;		
		RTable combinedRTable = rtable.combine(loc.rtable);
		this.rtable = combinedRTable;
		
	}
	
	@Override
	public boolean equals(RTableLatticeElement obj) {
		Boolean bool;
		RTable r1 = this.rtable;
		RTable r2 = obj.rtable;
		
		bool = r1.equals(r2);
		return bool;
	}

	@Override
	public boolean lessThan(RTableLatticeElement locElement) {
		return this.rtable.lessthan(locElement.rtable);
	}
	
	
}