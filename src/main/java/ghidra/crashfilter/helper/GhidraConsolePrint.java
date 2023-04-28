package ghidra.crashfilter.helper;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.ScriptMessage;
import ghidra.app.services.ConsoleService;
import ghidra.util.Msg;

public class GhidraConsolePrint {
	static private ConsoleService console = null;

	static public void setConsoleService(ConsoleService cService) {
		console = cService;
	}

	static public void println(String message) {
		String decoratedMessage = "CrashFilter" + "> " + message;
		decoratedMessage = decoratedMessage.strip();
		// note: use a Message object to facilitate script message log filtering
		Msg.info(GhidraScript.class, new ScriptMessage(decoratedMessage));

		if (console == null) {
			return;
		}

		try {
			console.addMessage("CrashFilter", message);
		} catch (Exception e) {
			console.addErrorMessage(e.toString(), "Ghidra print error");
		}
	}
}
