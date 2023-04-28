package ghidra.crashfilter.helper;


import ghidra.app.util.PseudoInstruction;
import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.Val;
import ghidra.crashfilter.memory.RTable.RTable;
import ghidra.crashfilter.memory.env.Env;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.mloc.StructuredMLoc;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlock;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CallStackCleaner {
	
	private static CallStackCleaner callStackCleaner;
	private boolean callStackFlag = false;
	
	private Function function;
	private ILatticeGraph<InstructionGraphNode> graph;
	private List<Instruction> toBeClearedInstList = new ArrayList<Instruction>();	
	
	public  CallStackCleaner initCallStackCleaner(Function func, ILatticeGraph<InstructionGraphNode> instgraph)
	{
		function = func;
		Listing list = func.getProgram().getListing();
		AddressSetView asv = func.getBody();
		
		
		for(InstructionGraphNode inst : instgraph.getNodes())
		{
			Address funcAddr = func.getBody().getFirstRange().getMinAddress();
			long funcAddrLong = funcAddr.getOffset();
			
			Instruction nativeInst = list.getInstructionAt(funcAddr);
			
			if(callStackFlag)
			{
				toBeClearedInstList.add(nativeInst);
				callStackFlag = false;
			}
			if(nativeInst.getMnemonicString().equals("call"))
			{
				callStackFlag = true;
			}
		}
		
		return callStackCleaner;
	}
	
	public static CallStackCleaner getCallStackCleaner()
	{
		if(callStackCleaner == null)
		{
			callStackCleaner = new CallStackCleaner();
		}
		return callStackCleaner;
	}
	
	public boolean isToBeClearedStack(InstructionGraphNode reilInst)
	{
		for(Instruction instruction : toBeClearedInstList)
		{			
			if(instruction.getAddress().getOffset() == reilInst.getAddr().getOffset())
			{
				return true;
			}
		}
		
		return false;
	}
	public void clearCallStack(InstructionGraphNode inst, RTable rTable, Env env)	
	{
		Address instAddr = inst.getPcode().getParent().getStart();
		Listing list = function.getProgram().getListing();
		Instruction nativeInst = list.getInstructionAt(instAddr);
		
		if(callStackFlag)
		{
			clearCallStack_Ebp(rTable, env);
			callStackFlag = false;
		}

		if(nativeInst.getMnemonicString().equals("CALL"))
		{
			callStackFlag = true;
		}
	}
	public void clearCallStack_Ebp(RTable rTable, Env env)
	{
		Set<IValue> values = rTable.get(new ActualReg("RSP"));
		Set<IValue> newValues = new HashSet<IValue>();
		for(IValue value : values)
		{
			if(value instanceof StructuredMLoc)
			{
				StructuredMLoc structuredValue = (StructuredMLoc) value;
				if(env.containsKey(structuredValue))
				{
					env.remove(structuredValue);
					Val ori = structuredValue.getC2();
					Val add4 = new Val(ori.getValue()+4);
					
					StructuredMLoc newStructuredValue = structuredValue.copy();
					newStructuredValue.setC2(add4);
					newValues.add(newStructuredValue);
				}
			}
		}
		rTable.remove(new ActualReg("RSP"));
		rTable.put(new ActualReg("RSP"), newValues);
	}
}
