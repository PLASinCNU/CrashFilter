package ghidra.crashfilter.helper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class VariableFinder {
	// Argument가 쓰인 곳에 대한 instruction을 다 가지고 있음
	// dest 또는 src건 상관 없이 def되건 use 되건 사용된 instruction
	private Program module;
	private Function function;

	private List<Symbol> globalVariables = new ArrayList<Symbol>();

	private Set<String> usedGlobalVariables = new HashSet<String>();
	private Set<String> usedLocalVariables = new HashSet<String>();
	private Set<String> usedArguments = new HashSet<String>();

	private Set<String> usedOperands = new HashSet<String>();

	private Set<Instruction> usedArgumentInstructions = new HashSet<Instruction>();
	private Set<Instruction> usedGlobalVariableInstructions = new HashSet<Instruction>();

	public Set<String> getUsedGlobalVariables() {
		return usedGlobalVariables;
	}

	public Set<String> getUsedLocalVariables() {
		return usedLocalVariables;
	}

	public Set<String> getUsedArguments() {
		return usedArguments;
	}

	public VariableFinder(Program module, Function function) {
		this.module = module;
		this.function = function;
		for (Symbol symbol : function.getProgram().getSymbolTable().getDefinedSymbols()) {
			if (symbol.getSymbolType().getID() == SymbolType.GLOBAL.getID()) {

			}
		}
		initGlobalVariables();

		usedOperands = findUsedOperands();

		findUsedLocalVariables();
		findUsedArguments();
		findUsedGlobalVariables();

		usedGlobalVariableInstructions = findGlobalVariableInstructions();
	}

	private HashSet<Instruction> findGlobalVariableInstructions() {

		HashSet<Instruction> usedGlobalVariableInstructions1 = new HashSet<Instruction>();
		for (Instruction inst : module.getListing().getInstructions(function.getBody(), true)) {
			for (int i = 0; i < inst.getNumOperands(); i++) {
				for (Symbol symbol : this.globalVariables) {
					if (inst.getDefaultOperandRepresentation(i).contains(symbol.getName()))
						usedGlobalVariableInstructions1.add(inst);
				}
			}
		}
		return usedGlobalVariableInstructions1;
	}

	private void initGlobalVariables() {
		for (Symbol symbol : module.getSymbolTable().getDefinedSymbols()) {
			if (symbol.getSymbolType().getID() == SymbolType.GLOBAL.getID()) {
				globalVariables.add(symbol);
			}
		}
	}

	private Set<String> findUsedOperands() {

		HashSet<String> usedOperands1 = new HashSet<String>();

		for (Parameter param : function.getParameters()) {
			usedOperands1.add(param.getName());
		}

		return usedOperands1;
	}

	private void findUsedGlobalVariables() {
		for (String operand : usedOperands) {
			for (Symbol symbol : globalVariables) {

				if (operand.contains(symbol.getName())) {
					System.out.println("global : " + symbol.getName());
					usedGlobalVariables.add(operand);
				}
			}
		}
	}

	private void findUsedLocalVariables() {
		for (Variable var : function.getLocalVariables()) {
			this.usedLocalVariables.add(var.getName());
		}

	}

	private void findUsedArguments() {
		for (Instruction inst : module.getListing().getInstructions(function.getBody(), true)) {
			
			for (Parameter param : function.getParameters()) {
				for (int i = 0; i < inst.getNumOperands(); i++) {
					if (inst.getOperandType(i) == OperandType.REGISTER) {
						if (inst.getDefaultOperandRepresentation(i).contains(param.getName()))
							this.usedArgumentInstructions.add(inst);
					} else if (inst.getOperandType(i) == OperandType.ADDRESS) {
						if (inst.getDefaultOperandRepresentation(i).contains(param.getName()))
							this.usedArgumentInstructions.add(inst);
					} else if (inst.getOperandType(i) == OperandType.SCALAR) {
						if (inst.getDefaultOperandRepresentation(i).contains(param.getName()))
							this.usedArgumentInstructions.add(inst);
					}
				}
			}
		}
	}

	public Set<Instruction> getUsedArgumentInstructions() {
		return usedArgumentInstructions;
	}

	public void setUsedArgumentInstructions(Set<Instruction> usedArgumentInstructions) {
		this.usedArgumentInstructions = usedArgumentInstructions;
	}

}
