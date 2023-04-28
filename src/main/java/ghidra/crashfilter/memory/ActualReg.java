package ghidra.crashfilter.memory;

import java.util.HashMap;
import java.util.List;

import ghidra.crashfilter.memory.interfaces.IRegister;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

public class ActualReg implements IRegister, IValue
{
	String rname;
	
	public static ActualReg STACK = new ActualReg("stack");
	public static ActualReg HEAP = new ActualReg("heap");
	public static ActualReg OLDEBP = new ActualReg("oldebp");
	public static ActualReg RETADDR = new ActualReg("retAddr");
	

	
	
	public static HashMap<String, ActualReg> regMap = new HashMap<>();
	
	public static void initActualReg(Language lang) {
		
		for(Register reg: lang.getRegisters()) {
			ActualReg actReg = new ActualReg(reg);
			regMap.put(reg.getName(), actReg);
		}
	}
	
	public static ActualReg getActualReg(String rname) {
		if(regMap.containsKey(rname)) return regMap.get(rname);
		return new ActualReg(rname);
	}
	
	public ActualReg(String rname) { this.rname = rname;}
	public ActualReg(Register rname) { this.rname = rname.getName();}


	public String getRegName(){ return rname;}
	@Override
	public String toString() {	return rname;}
	@Override
	public int hashCode() {
		// TODO Auto-generated method stub
		return rname.hashCode();
	}
	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		if(obj.getClass() != ActualReg.class)
		{
			return false;
		}
		ActualReg t = (ActualReg)obj;
		boolean bool =  this.rname.equals(t.rname);
		return bool;
	}
}

