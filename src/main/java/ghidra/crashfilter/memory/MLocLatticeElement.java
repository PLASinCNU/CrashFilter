package ghidra.crashfilter.memory;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;
import ghidra.crashfilter.memory.RTable.RTable;
import ghidra.crashfilter.memory.env.Env;

public class MLocLatticeElement implements ILatticeElement<MLocLatticeElement>{
	private InstructionGraphNode inst;
	private Env env;
	private RTable rTable;
	//getter & setter
	public MLocLatticeElement()
	{
		env = new Env();
		rTable = new RTable();
	}
	public Env getEnv()
	{
		return this.env;
	}
	public void setEnv(Env env)
	{
		this.env = env;
	}
	public RTable getRTable()
	{
		return this.rTable;
	}
	public void setRTable(RTable rTable)
	{
		this.rTable = rTable;
	}
	public void setInst(InstructionGraphNode inst)
	{
		this.inst = inst;
	}
	public InstructionGraphNode getInst()
	{
		return inst;
	}
	public void combine( MLocLatticeElement mLocLatticeElement)
	{
		env = env.combine(mLocLatticeElement.env);
		rTable = rTable.combine(mLocLatticeElement.rTable);
	}

	public boolean equals(MLocLatticeElement mLocLatticeElement) {
		boolean returnValue = env.equals(mLocLatticeElement.env)&&rTable.equals(mLocLatticeElement.rTable); 
		return returnValue;
	}

	public boolean lessThan(MLocLatticeElement mLocLatticeElement) {
		boolean returnValue = env.lessthan(mLocLatticeElement.env)||rTable.lessthan(mLocLatticeElement.rTable);
		return returnValue;
	}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
	
}
