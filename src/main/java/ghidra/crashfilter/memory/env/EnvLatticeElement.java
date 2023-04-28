package ghidra.crashfilter.memory.env;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeElement;

public class EnvLatticeElement implements ILatticeElement<EnvLatticeElement>{
	private InstructionGraphNode inst;
	private Env env;

	
	
	public EnvLatticeElement()
	{
		env = new Env();
	}
	
	public void setEnv(Env env)
	{
		this.env = env;
	}
	public void setInst(InstructionGraphNode inst)
	{
		this.inst = inst;
	}
	public InstructionGraphNode getInst()
	{
		return inst;
	}
	public Env getEnv()
	{
		return this.env;
	}
	
	public void combine( EnvLatticeElement envLatticeElement)
	{		
		this.inst = envLatticeElement.inst;
		
		Env combinedEnv = env.combine(envLatticeElement.env);
		this.env = combinedEnv;
		
	}
	
	@Override
	public boolean equals(EnvLatticeElement obj) {
		Boolean bool;
		Env e1 = this.env;
		Env e2 = obj.env;
		
		bool = e1.equals(e2);
		return bool;
	}

	@Override
	public boolean lessThan(EnvLatticeElement EnvElement) {
		return this.env.lessthan(EnvElement.env);
		//return false;
	}
	
	
}