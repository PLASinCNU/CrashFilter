import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.crashfilter.CrashFilterAnalyzer;
import ghidra.crashfilter.Dangerousness;
import ghidra.crashfilter.helper.InterProcedureMode;
import ghidra.crashfilter.helper.PseudoProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class CrashFilter extends GhidraScript {
	// Store instruction 은 out 이 없고 input 1 이 destination 메모리 
	// 2가 저장할 내용
	// 0은 const 인데 무엇인지 잘 모르겠음
	// LOAD 의 input 0 도 const 이고 필요없음
	// LOAD 는 output이 있음 
	
	Language lang;
	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		if (currentProgram == null) {
			throw new NullPointerException("No program available, exit!\n");
		}
		Program prog = this.getCurrentProgram();
		lang = prog.getLanguage();
		Listing listing = prog.getListing();
		String crashAddr = this.askString("Crash address", "Crash address");
		PseudoDisassembler pdis;
		AddressFactory addressFactory = prog.getAddressFactory();
		Address crashPointAddress = addressFactory.getAddress(crashAddr);
		Function curFunc = prog.getFunctionManager().getFunctionContaining(crashPointAddress);

	
		CrashFilterAnalyzer analyzer = new CrashFilterAnalyzer(prog);
		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		ConsoleService console = tool.getService(ConsoleService.class);
		analyzer.setConsole(console);
		
		Dangerousness rate = analyzer.crashAnalyze(crashAddr);
		println("this crash's rate is " +  rate.toString());
	}

}
