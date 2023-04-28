//@author youjeong.Noh
//@category _NEW_

package crashfilter.wrapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;

public class WrapperFunction {
	
	/* fields */
	protected Module parent;
	protected TaskMonitor monitor = null;

	protected ghidra.program.model.listing.Function function;

	/* getter, setter */
	public Module getParent() {
		return parent;
	}
	public void setParent(Module parent) {
		this.parent = parent;
	}
	public TaskMonitor getMonitor() {
		return monitor;
	}
	public void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}
	public void setFunction(ghidra.program.model.listing.Function function) {
		this.function = function;
	}
	public ghidra.program.model.listing.Function getFunction() {
		return function;
	}
	
	
	/* constructor */
	private WrapperFunction(Module parent, ghidra.program.model.listing.Function function) {
		super();
		this.parent = parent;
		this.function = function;
	}
	
	
	/* functions */
	
	/* Static Factory Method */
	public static WrapperFunction createFunction(Module parent, ghidra.program.model.listing.Function function) {
		return new WrapperFunction(parent, function);
	}
	
	
	public HighFunction decompile(Program program) {
		
		FunctionManager functionManager = program.getFunctionManager();
		ghidra.program.model.listing.Function func = functionManager.getFunctionContaining(function.getEntryPoint());
//		ghidra.program.model.listing.Function func = functionManager.getFunctionContaining(null);
		
		DecompileOptions dOptions = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();

		ifc.setOptions(dOptions);
		ifc.openProgram(program);

		DecompileResults dResults = ifc.decompileFunction(func, 10, monitor);
		HighFunction dFunc = dResults.getHighFunction();
		
		return dFunc;
	}
	
	public List<WrapperBasicBlock> getBasicBlocks() {
		// 리턴할 BasicBlock 리스트
		List<WrapperBasicBlock> BBList = new ArrayList<>();

		HighFunction dFunc = decompile(parent.getProgram());
		for (final PcodeBlockBasic block : dFunc.getBasicBlocks()) {
			BBList.add(WrapperBasicBlock.createBasicBlock(this, block));
		}
		return BBList;
	}

	public List<WrapperPcode> getPcodes() {
		// 리턴할 Pcode 리스트
		List<WrapperPcode> PcodeList = new ArrayList<WrapperPcode>();
		
		HighFunction dFunc = decompile(parent.getProgram());
		for (final PcodeBlockBasic block : dFunc.getBasicBlocks()) {
			Iterator<PcodeOp> iter = block.getIterator();
			
			PcodeOp pcode;
			while (iter.hasNext()) {
				pcode = iter.next();
				PcodeList.add(WrapperPcode.createPcode(WrapperBasicBlock.createBasicBlock(this, block), pcode));
				
				System.out.println(pcode.toString());
			}
			System.out.println("--------------- bb end --------------------");
		}
		return PcodeList;
	}

	/* getCaller, getCallee 함수는 우선사항 아님.
	   각각, 해당 function을 호출하는 caller와 함수 내에서 로출하는 함수인 callee의 List를 갖고오는 함수임 */
	public List<WrapperFunction> getCaller() {
		List<WrapperFunction> callerFuncList = new ArrayList<>();
		
		List<ghidra.program.model.listing.Function> funcList = new ArrayList<>();
		funcList.addAll(function.getCallingFunctions(monitor));
		
		Iterator<ghidra.program.model.listing.Function> funcIter = funcList.iterator();
		while (funcIter.hasNext()) {
			ghidra.program.model.listing.Function f = funcIter.next();
			WrapperFunction func = new WrapperFunction(Module.createModule(f.getProgram()), f);
			callerFuncList.add(func);
		}
		return callerFuncList;
	}
	public List<WrapperFunction> getCallee() {
		List<WrapperFunction> calleeFuncList = new ArrayList<>();

		List<ghidra.program.model.listing.Function> funcList = new ArrayList<>();
		funcList.addAll(function.getCalledFunctions(monitor));

		Iterator<ghidra.program.model.listing.Function> funcIter = funcList.iterator();
		while (funcIter.hasNext()) {
			ghidra.program.model.listing.Function f = funcIter.next();
			WrapperFunction func = new WrapperFunction(Module.createModule(f.getProgram()), f);
			calleeFuncList.add(func);
		}
		return calleeFuncList;
	}

}
