package ghidra.crashfilter.memory;

import ghidra.crashfilter.memory.interfaces.IALoc;
import ghidra.crashfilter.memory.interfaces.IMLoc;
import ghidra.crashfilter.memory.interfaces.IValue;
import ghidra.crashfilter.memory.mloc.MLocTypes;
import ghidra.program.model.pcode.Varnode;

public class Val implements IMLoc, IValue, IALoc {
    int size;
    long value;

    public Val(long val) {
        this(4, val);
    }

    Val(int s, long val) {
        if (!(s == 1 | s == 2 | s == 4 | s == 8)) // number of bytes
            size = 4;
        else
            size = s;
        value = val;
    }

    // add two consts
    public static Val add(Val v1, Val v2) {
        int size = v1.size; // temporary, should be adjusted later
        return new Val(size, v1.value + v2.value);
    }

    public static Val sub(Val v1, Val v2) {
        int size = v1.size; // temporary, should be adjusted later
        return new Val(size, v1.value - v2.value);
    }

    public long getValue() {
        return this.value;
    }

    public static Val newVal(Varnode op) {
        long val = op.getOffset();
        return new Val(val);
    }


    public MLocTypes getMLocType() {
        return MLocTypes.ValConst;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return "[Val : " + value + "]";
    }

    @Override
    public int hashCode() {
        // TODO Auto-generated method stub
        return new Long(this.value).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        // TODO Auto-generated method stub
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        Val o = (Val) obj;

        return o.value == this.value;
    }

}
