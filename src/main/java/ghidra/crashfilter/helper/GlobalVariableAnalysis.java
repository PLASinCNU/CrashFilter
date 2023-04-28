package ghidra.crashfilter.helper;



import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class GlobalVariableAnalysis {
    private Function currentFunction;
    private VariableFinder variableFinder;
    private Set<String> usedGlobalVariables;
    
    public Set<String> getUsedGlobalVariables() {
        return usedGlobalVariables;
    }

    public GlobalVariableAnalysis(Program module, Function function) {
        
        currentFunction = function;
        variableFinder = new VariableFinder(module, currentFunction);    
        usedGlobalVariables = this.variableFinder.getUsedGlobalVariables();

    }
    
    public boolean dontUseGlobalVariable() {
        return variableFinder.getUsedGlobalVariables().size() == 0;
    }
    
    
    public boolean hasSameGlobalVaraible(GlobalVariableAnalysis globalVariableAnalysis) {
        for(String thisVariable : usedGlobalVariables)
        {
            for(String anotherVariable : globalVariableAnalysis.usedGlobalVariables)
            {
                if(thisVariable.equals(anotherVariable))
                {
                    return true;
                }
            }
        }
        return false;        
    }
    
}
