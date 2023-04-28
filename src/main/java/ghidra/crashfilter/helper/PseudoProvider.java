package ghidra.crashfilter.helper;

import java.util.ArrayList;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class PseudoProvider {
	static private PseudoProvider pseudoProvider = null;
	PseudoDisassembler pdis = null;

	public ArrayList<PseudoInstruction> getPseudos(Function func) {
		ArrayList<PseudoInstruction> pSeudos = new ArrayList<>();

		AddressSetView asv = func.getBody();

		for (Address addr = asv.getMinAddress(); addr.getOffset() <= asv.getMaxAddress().getOffset();) {

			PseudoInstruction psi = null;
			try {
				psi = pdis.disassemble(addr);
				
				if (psi == null) {
					addr = addr.next();
					continue;  
				}
				
				addr = addr.getNewAddress(addr.getOffset() + psi.getLength());
				pSeudos.add(psi);
			} catch (InsufficientBytesException | UnknownInstructionException | UnknownContextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return pSeudos;
	}
	public PseudoInstruction getPseudo(Address addr) {
		PseudoInstruction psi = null;
		try {
			psi = pdis.disassemble(addr);
						
		} catch (InsufficientBytesException | UnknownInstructionException | UnknownContextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return psi;
	}
	private PseudoProvider(Program prog) {
		pdis = new PseudoDisassembler(prog);
		// TODO Auto-generated constructor stub
	}
	
	static public PseudoProvider getPseudoProvider(Program prog) {
		if(pseudoProvider == null) {
			pseudoProvider = new PseudoProvider(prog);
		}
		return pseudoProvider;
	}
	
	static public String getAppendAddressIndex(Address addr, int index) {
		String appendString = "";
		appendString += addr.toString()+Integer.toHexString(index);
		return appendString;
	}
}
