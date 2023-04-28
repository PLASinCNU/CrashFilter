package ghidra.crashfilter.memory.mloc;

import ghidra.crashfilter.helper.GhidraConsolePrint;
import ghidra.crashfilter.memory.ActualReg;
import ghidra.crashfilter.memory.TempReg;
import ghidra.crashfilter.memory.interfaces.IRegister;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public class MFactoryHelper {
	private static Language lang = null;

	public static StructuredMLoc newStructuredMLocFromOp() {
		return null;
	}

	public static void setLangeuage(Language language) {
		lang = language;
	}

	public static IRegister newIRegister(Varnode op) {
		if (op.isUnique())
			return new TempReg(Long.toHexString(op.getOffset()));
		if (op.isRegister()) {
			if (lang == null)
				return null;
			Register reg = lang.getRegister(op.getAddress(), op.getSize());
			// GhidraConsolePrint.println(reg.getName());
			return new ActualReg(reg.getName());
		}
		return null;
	}

	public static IRegister newIRegister(String str) {
		return new ActualReg(str);
	}
}
