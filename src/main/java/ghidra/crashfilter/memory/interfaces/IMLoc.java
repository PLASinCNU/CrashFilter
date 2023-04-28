package ghidra.crashfilter.memory.interfaces;

import ghidra.crashfilter.memory.mloc.MLocTypes;

public interface IMLoc extends IALoc {
    public MLocTypes getMLocType();
}
