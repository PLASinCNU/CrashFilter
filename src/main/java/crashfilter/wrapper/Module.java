//@author youjeong.Noh
//@category _NEW_

package crashfilter.wrapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

//An address represents a location in a program.
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

// Module means a program.
public class Module {

	/* fields */
	protected Program program;

	/* getter, setter */
	public Program getProgram() {
		return program;
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	/* constructor */
	private Module(Program program) {
		super();
		this.program = program;
	}

	/* functions */
	public static Module createModule(Program program) {
		return new Module(program);
	}
//	public static Module createCurrentModule() {
//		return new Module(currentProgram);
//	}
	
	public WrapperFunction getFunction(String name) {
		Listing listing = program.getListing();
		Iterator<Function> funcIter = listing.getFunctions(true);

		while (true) {
			if (!funcIter.hasNext()) {
				System.out.println("error: There is no function with name, \"" + name + "\"");
				break;
			}

			Function func = funcIter.next();
			if (func.getName().equals(name)) {
				return WrapperFunction.createFunction(this, func);
			}
		}
		// 찾는 이름의 함수 없으면 null 리턴
		return null;
	}

	public WrapperFunction getFunction(Address addr) {
		Listing listing = program.getListing();
		if (listing.getFunctionAt(addr) != null) {
			return WrapperFunction.createFunction(this, listing.getFunctionAt(addr));
		}
		// 찾는 주소의 함수 없으면 null 리턴
		System.out.println("error: There is no function with address, \"" + addr + "\"");
		return null;
	}

	public List<WrapperFunction> getFunctions() {
		// 리턴할 Function 리스트
		List<WrapperFunction> funcList = new ArrayList<>();

		Listing listing = program.getListing();
		Iterator<Function> funcIter = listing.getFunctions(true);
		while (funcIter.hasNext()) {
			funcList.add(WrapperFunction.createFunction(this, funcIter.next()));
		}
		return funcList;
	}

}