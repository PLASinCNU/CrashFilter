package ghidra.crashfilter.memory.RTable;


import java.util.AbstractMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.pcode.PcodeOp;


public class Inst2RTable	extends AbstractMap<PcodeOp, RTable>
							implements Map<PcodeOp, RTable> 
{
	
	Inst2RTable(){
		tableEntries = new HashSet<java.util.Map.Entry<PcodeOp, RTable>>();
	}
	Set<java.util.Map.Entry<PcodeOp, RTable>> tableEntries;
	
	public RTable put(PcodeOp e, RTable rt){
		tableEntries.add(new AbstractMap.SimpleEntry<PcodeOp,RTable>(e, rt));
		return rt;
	}
	
	@Override
	public Set<java.util.Map.Entry<PcodeOp, RTable>> entrySet() {
		return tableEntries; 
	}
}
