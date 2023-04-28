package ghidra.crashfilter.memory.RTable;

import java.util.*;

import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.TempReg;
import ghidra.crashfilter.memory.Val;
import ghidra.crashfilter.memory.interfaces.IALoc;
import ghidra.crashfilter.memory.interfaces.IRegister;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.interfaces.IValueGrade;
import ghidra.crashfilter.memory.mloc.MFactoryHelper;
import ghidra.crashfilter.memory.mloc.StructuredMLoc;
import ghidra.crashfilter.memory.mloc.Symbol_Bottom;
import ghidra.crashfilter.memory.mloc.Symbol_Top;
import ghidra.program.model.pcode.Varnode;

public class RTable extends AbstractMap<IRegister, Set<IValue>> implements Map<IRegister, Set<IValue>> {

	private Set<java.util.Map.Entry<IRegister, Set<IValue>>> tableEntries;

	public Set<IValue> put(IRegister s, Set<IValue> v) {
		tableEntries.add(new AbstractMap.SimpleEntry<IRegister, Set<IValue>>(s, v));
		return v;
	}

	public RTable() {
		tableEntries = new HashSet<java.util.Map.Entry<IRegister, Set<IValue>>>();
	}

	public RTable copy() {
		Iterator<Entry<IRegister, Set<IValue>>> iter = tableEntries.iterator();
		RTable result = new RTable();
		while (iter.hasNext()) {
			Entry<IRegister, Set<IValue>> ent = iter.next();

			IRegister r = ent.getKey();
			if (r instanceof ActualReg) {
				// nothing have to do.
			} else if (r instanceof TempReg) {
				r = new TempReg(((TempReg) r).getRegName());
			}
			Set<IValue> saveVT;
			Set<IValue> vT = ent.getValue();

			saveVT = copyIValueSet(vT);

			result.put(r, saveVT);
		}
		return result;

	}

	private Set<IValue> copyIValueSet(Set<IValue> vT) {
		if (vT == null) {
			return null;
		}
		Set<IValue> saveVT = new HashSet<IValue>();
		for (IValue value : vT) {
			IValue copyValue = null;
			if (value instanceof Val) {
				Val val = new Val(((Val) value).getValue());
				copyValue = val;

			} else if (value instanceof StructuredMLoc) {
				StructuredMLoc val = ((StructuredMLoc) value).copy();
				copyValue = val;
			} else {
				copyValue = value; // top or bottom..
			}

			saveVT.add(copyValue);
		}
		return saveVT;
	}

	public RTable combine(RTable rtable) {
		RTable result = null;
		RTable r1 = this.copy();
		RTable r2 = rtable.copy();
		Set<IRegister> r1Key = r1.keySet();
		Set<IRegister> r2Key = r2.keySet();

		for (IRegister r2k : r2Key) {
			if (r1.containsKey(r2k)) {
				Set<IValue> value = combineIValueSet(r1.get(r2k), r2.get(r2k));
				r1.put(r2k, value);
			} else {
				r1.put(r2k, r2.get(r2k));
			}
		}
		result = r1;
		return result;
	}

	public Set<IValue> combineIValueSet(Set<IValue> vs1, Set<IValue> vs2) {
		Set<IValue> result = new HashSet<IValue>();
		for (IValue v1 : vs1) {
			result.add(v1);
		}
		for (IValue v2 : vs2) {
			result.add(v2);
		}

		return result;
	}

	public boolean lessthan(RTable rt2) {
		// return !this.equals(rt2);
		if (this == rt2 || this.equals(rt2)) {
			return false;
		}

		Set<IRegister> r1keys = this.keySet();
		Set<IRegister> r2keys = rt2.keySet();

		for (IRegister r1 : r1keys) {
			if (rt2.containsKey(r1)) {
				IValueGrade r1g = IValueGrade.getValueSetSymbol(this.get(r1));
				IValueGrade r2g = IValueGrade.getValueSetSymbol(rt2.get(r1));
				if (r2g.gradeValue > r1g.gradeValue) {
					return true;
				}
			} else {
				return false;
			}
		}
		// TODO
		return false;

	}

	public IValue checkStackOrHEapMemory(Varnode op) {
		boolean stack = false;
		boolean heap = false;
		IValue result = null;
		IRegister reg = MFactoryHelper.newIRegister(op);
		if (reg instanceof ActualReg) {

			Set<IValue> vals = this.get(reg);
			for (IValue v : vals) {
				if (v instanceof Symbol_Bottom) {
				} else if (v instanceof Symbol_Top) {
					return Symbol_Top.getSymbolTop();
				} else if (v instanceof StructuredMLoc) {
					StructuredMLoc st = (StructuredMLoc) v;
					if (st.getReg2().equals(new ActualReg("stack"))) {
						stack = true;
					}
				} else if (v instanceof IRegister) {
					IRegister r = (IRegister) v;
					if (r.equals(new ActualReg("heap"))) {
						heap = true;
					}
				}

			}
		} else {
			return null;
		}

		if (stack == true && heap == false) {
			return new ActualReg("stack");
		} else if (stack == false && heap == true) {
			return new ActualReg("stack");
		} else if (stack == false && heap == false) {
			return Symbol_Bottom.getSymbolBottom();
		} else if (stack == false && heap == false) {
			return Symbol_Top.getSymbolTop();
		}

		return null;

	}

	@Override
	public Set<java.util.Map.Entry<IRegister, Set<IValue>>> entrySet() {
		return tableEntries;
	}

	@Override
	public boolean equals(Object o) {
		// TODO Auto-generated method stub

		if (this == o) {
			return true;
		}

		if (!(o instanceof RTable)) {
			return false;
		}
		RTable rtable2 = (RTable) o;
		Set<IRegister> rs1 = this.keySet();
		Set<IRegister> rs2 = rtable2.keySet();

		if (!(rs1.containsAll(rs2) && rs2.containsAll(rs1))) {
			return false;
		}

		for (IRegister r1 : rs1) {
			Set<IValue> vs1 = this.get(r1);
			Set<IValue> vs2 = rtable2.get(r1);
			if (!(vs1.equals(vs2))) {
				return false;
			}
		}

		return true;
	}

	public void heapChanger() {
		this.get(new ActualReg("eax")).add(new ActualReg("heap"));
	}

	public void initTest(int i) {
		Set<IValue> v = new HashSet<IValue>();
		v.add(new Val(i));
		this.put(new ActualReg("eax"), v);
	}

	public void printRTable() {
		for (IRegister reg : this.keySet()) {
			// LogConsole.log("Key : "+reg+"\n");
			for (IValue value : this.get(reg)) {
				// LogConsole.log("\tValue : "+value+"\n" );
			}

		}
	}

	public void deleteTempReg() {

		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IRegister> keyset = this.keySet();
		for (IRegister key : keyset) {
			if (key instanceof TempReg) {
				toBeRemoved.add(key);
			}
		}
		for (IALoc key : toBeRemoved) {
			this.remove(key);
		}

	}

	public void deleteNullNBottom() {
		Set<IALoc> toBeRemoved = new HashSet<IALoc>();
		for (IALoc key : keySet()) {
			GhidraConsolePrint.println("delete"+ key.toString());
			Set<IValue> valueSet = get(key);
			if (valueSet.size() == 1 && valueSet.contains(Symbol_Bottom.getSymbolBottom())) {
				toBeRemoved.add(key);
			}
			if (valueSet.size() == 0) {
				toBeRemoved.add(key);
			}
		}

		for (IALoc key : toBeRemoved) {
			this.remove(key);
		}

	}

}
