package ghidra.crashfilter.helper;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class InterProcedureAnalysis {

    private FunctionCallAnalysis functionCallAnalysis ;
    private GlobalVariableAnalysis globalVariableAnalysis;
    
    public InterProcedureAnalysis(Program module, Function curFunc){
    
        functionCallAnalysis = new FunctionCallAnalysis(module, curFunc);
        globalVariableAnalysis = new GlobalVariableAnalysis(module, curFunc);
    }

    public boolean needAnalysis() {
        
        boolean needGlobalVariableAnalysis = !globalVariableAnalysis.dontUseGlobalVariable();        
        
        if(needGlobalVariableAnalysis)
        {
            System.out.println("need global Variable Analysis");
        }
        return (needGlobalVariableAnalysis);
    }

    
}
