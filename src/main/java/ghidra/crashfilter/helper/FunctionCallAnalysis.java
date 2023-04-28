package ghidra.crashfilter.helper;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class FunctionCallAnalysis {

	private Function currentFunction;
	private VariableFinder variableFinder;
	private Program module;
	private Set<Function> callees;

	public Set<Function> getCallees() {
		return callees;
	}

	public FunctionCallAnalysis(Program module, Function function) {
		currentFunction = function;
		variableFinder = new VariableFinder(module, currentFunction);
		this.module = module;

		callees = function.getCalledFunctions(null);
	}

	public Set<Function> getCallees(Function function) {
		return callees;
	}

	public boolean dontHaveArgument() {
		return variableFinder.getUsedArguments().size() == 0;
	}

}
